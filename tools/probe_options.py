import argparse
import hashlib
import tempfile
import ipaddress
import json
import os
import shutil
import stat
import sys
from tempfile import TemporaryDirectory
from pathlib import Path


def ipv4(value: str) -> str:
    try:
        address = ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError as exc:
        raise argparse.ArgumentTypeError("target must be one IPv4 address") from exc
    if address.is_multicast or address.is_unspecified or address.is_reserved or address.packed[0] == 0:
        raise argparse.ArgumentTypeError("target must be one unicast IPv4 address, not unspecified, multicast or reserved")
    return str(address)


def port(value: str) -> int:
    try:
        number = int(value)
        if not 1 <= number <= 65535:
            raise ValueError()
        return number
    except ValueError as exc:
        raise argparse.ArgumentTypeError("port must be between 1 and 65535") from exc


def ports(value: str) -> list[int]:
    try:
        values = sorted({port(item.strip()) for item in value.split(",")})
        if not values:
            raise ValueError()
        return values
    except (ValueError, argparse.ArgumentTypeError) as exc:
        raise argparse.ArgumentTypeError("ports must be a nonempty comma-separated list of 1..65535") from exc


def validate_report_paths(inputs: list[Path], outputs: list[Path]) -> None:
    runtime = [__file__, sys.executable] + [vars(module).get('__file__') for module in tuple(sys.modules.values()) if module is not None]
    seen = [*inputs, *(Path(filename) for filename in runtime if filename)]
    for output in outputs:
        try:
            info = output.lstat()
        except FileNotFoundError:
            pass
        else:
            if not stat.S_ISREG(info.st_mode) or info.st_nlink > 1:
                raise ValueError(f"Report must be a regular, unlinked file: {output}")
        if any(output.resolve() == source.resolve() or (
            output.exists() and source.exists() and output.samefile(source)
        ) for source in seen):
            raise ValueError("Reports must not overwrite inputs or other reports")
        seen.append(output)


def report_output(value: str) -> Path:
    output = Path(value)
    try:
        validate_report_paths([], [output])
    except (OSError, RuntimeError, ValueError) as error:
        raise argparse.ArgumentTypeError(str(error)) from error
    return output



def output_state(path, allowed_links=1):
    try:
        before = path.lstat()
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != allowed_links:
        raise ValueError(f"Output must be a regular file without links: {path}")
    digest = hashlib.sha256(path.read_bytes()).digest()
    after = path.lstat()
    identity = lambda info: (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
    if identity(before) != identity(after) or after.st_nlink != allowed_links:
        raise ValueError(f"Output changed while reading: {path}")
    return identity(after)[:4], digest


def publish_output(draft, destination, baseline):
    def publish(source, target):
        if os.name == "nt":
            source.rename(target)
        else:
            os.link(source, target)
            source.unlink()

    expected = output_state(draft)
    folder = Path(tempfile.mkdtemp(prefix=".output-recovery-", dir=destination.parent))
    backup, moved = folder / "previous", folder / "published"
    old_saved = published = False
    try:
        if baseline is not None:
            destination.rename(backup)
            old_saved = True
            if output_state(backup) != baseline:
                raise FileExistsError(f"Output changed during operation: {destination}")
        if os.name == "nt":
            draft.rename(destination)
            published = True
        else:
            os.link(draft, destination)
            published = True
            draft.unlink()
    except BaseException as error:
        failures = []
        if published and os.path.lexists(destination):
            try:
                destination.rename(moved)
                try:
                    links = 1
                    if os.path.lexists(draft):
                        if not os.path.samefile(draft, moved):
                            raise FileExistsError(f"Staged output changed: {draft}")
                        links += 1
                    info = moved.lstat()
                    if not stat.S_ISREG(info.st_mode) or info.st_nlink != links:
                        raise FileExistsError(f"Output changed during rollback: {destination}")
                    current = ((info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns),
                               hashlib.sha256(moved.read_bytes()).digest())
                    if current != expected:
                        raise FileExistsError(f"Output changed during rollback: {destination}")
                except BaseException:
                    publish(moved, destination)
                    raise
                moved.unlink()
            except (OSError, ValueError) as failure:
                failures.append(str(failure))
        if old_saved:
            try:
                publish(backup, destination)
            except OSError as failure:
                failures.append(str(failure))
        if failures:
            recovery = ", ".join(str(path) for path in (backup, moved) if os.path.lexists(path)) or str(folder)
            raise OSError(f"Output rollback could not finish. recovery file: {recovery}; "
                          f"recovery directory: {folder}: " + "; ".join(failures)) from error
        raise
    else:
        if old_saved:
            try:
                backup.unlink()
            except OSError as error:
                raise OSError(f"Output published; recovery file: {backup}: {error}") from error
    finally:
        active_error = sys.exc_info()[1]
        try:
            folder.rmdir()
        except OSError as cleanup_error:
            if not os.path.lexists(backup) and not os.path.lexists(moved):
                raise OSError(f"Output cleanup failed; recovery directory: {folder}: {cleanup_error}") from (active_error or cleanup_error)

def parse_probe_args(parser):
    parser.add_argument("--out", required=True, type=report_output)
    parser.add_argument("--overwrite", action="store_true", help="Replace an existing regular report file")
    args = parser.parse_args()
    if args.out.exists() and not args.overwrite:
        parser.error(f"Report already exists: {args.out}. Use --overwrite to replace it.")
    args.output_baseline = output_state(args.out)
    return args


def stage_report(path, content):
    with path.open("x", encoding="utf-8") as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())


def publish_new(source, destination):
    if os.name == "nt":
        source.rename(destination)
    else:
        os.link(source, destination)


def write_probe(parser, args, result):
    try:
        with TemporaryDirectory(prefix=".network-report-", dir=args.out.parent) as folder:
            draft = Path(folder) / "report"
            stage_report(draft, json.dumps(result, ensure_ascii=False, indent=2))
            validate_report_paths([], [args.out])
            publish_output(draft, args.out, args.output_baseline)
    except FileExistsError:
        parser.error(f"Report already exists: {args.out}. Use --overwrite to replace it.")
    except (OSError, RuntimeError, ValueError) as error:
        parser.error(str(error))



def write_reports(inputs, reports, baselines=None):
    outputs = list(reports)
    validate_report_paths(inputs, outputs)
    if baselines is None:
        baselines = {output: output_state(output) for output in outputs}
    # The fixed staging directory serializes collectors updating the same result directory.
    folder = outputs[0].parent / ".network-reports-stage"
    folder.mkdir()
    backups, published = {}, {}
    preserve_recovery = False
    try:
        for index, content in enumerate(reports.values()):
            stage_report(folder / f"{index}.new", content)
        validate_report_paths(inputs, outputs)
        for index, output in enumerate(outputs):
            if baselines[output] is not None:
                backup = folder / f"{index}.old"
                output.rename(backup)
                backups[output] = backup
                if output_state(backup) != baselines[output]:
                    raise FileExistsError(f"Report changed during operation: {output}")
            draft = folder / f"{index}.new"
            identity = output_state(draft)
            publish_new(draft, output)
            published[output] = identity
            draft.unlink(missing_ok=True)
    except BaseException as error:
        rollback_errors = []
        for index in reversed(range(len(outputs))):
            output = outputs[index]
            quarantined = folder / f"{index}.published"
            try:
                if output in published and os.path.lexists(output):
                    output.rename(quarantined)
                    try:
                        draft = folder / f"{index}.new"
                        links = 1
                        if os.path.lexists(draft):
                            if not os.path.samefile(draft, quarantined):
                                raise FileExistsError(f"Staged report changed: {draft}")
                            links += 1
                        if output_state(quarantined, allowed_links=links) != published[output]:
                            raise FileExistsError(f"Report changed during rollback: {output}")
                    except BaseException:
                        publish_new(quarantined, output)
                        raise
                if output in backups:
                    publish_new(backups[output], output)
            except (OSError, ValueError) as restore_error:
                rollback_errors.append(str(restore_error))
        if rollback_errors:
            preserve_recovery = True
            raise OSError(f"Report rollback could not finish. Recovery files: {folder}. "
                          + " ".join(rollback_errors)) from error
        raise
    finally:
        if not preserve_recovery:
            active_error = sys.exc_info()[1]
            try:
                shutil.rmtree(folder)
            except OSError as cleanup_error:
                raise OSError(f"Report cleanup failed; recovery files: {folder}: {cleanup_error}") from (active_error or cleanup_error)
