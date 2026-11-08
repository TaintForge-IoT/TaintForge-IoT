"""Preserve earlier reports before exporting a resumed run."""
import os
from support import digest, export_reports, require


def preserve(path):
    if not path.exists():
        return
    saved = path.with_name(path.stem + '.before-resume.' + digest(path) + path.suffix)
    if saved.exists():
        require(digest(saved) == digest(path), 'Preserved historical artifact differs')
    else:
        os.link(path, saved)


def export(work):
    archive = work / ('taintforge_regression_' + work.name + '_reports.zip')
    if archive.exists():
        saved = archive.with_name(archive.stem + '.before-resume.' + digest(archive) + '.zip')
        if saved.exists():
            require(digest(saved) == digest(archive), 'Previous report preservation differs')
        else:
            os.link(archive, saved)
        archive.unlink()
    return export_reports(work)
