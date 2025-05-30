This package uses GitHub workflows for automated tests, reviewable.io for code reviews. We strongly recommend setting up ``pre-commit`` so that the basic style and formatting checks run as part of your ``git commit`` hooks.

Releases
========

Netconan has not yet released a 1.0.0 release, so we are using alpha releases in the 0.xx.yy series. The version number is stored in ``netconan/__init__.py``. On the master branch, it is always ``0.<next-minor>.0.dev``, while in release branches we remove the ``.dev``.

Release branches
---------------

All releases are cut from release branches named ``release-0.xx`` branch. Note that we do not include the ``.yy`` extension for the ``patch`` version in the branch name. Instead, the same branch contains a series of commits corresponding to the patches.

Suppose that the latest release was ``v0.12.3``. That means that in the master branch, the version is listed as ``0.13.0.dev`` and the next minor release will be ``v0.13.0``.

1. To create the branch, run ``git checkout -b release-0.13``.
2. Modify ``netconan/__init__.py`` and update the version to ``0.13.0`` (remove the ``.dev``).
3. Commit the version change and push the branch to GitHub.
4. Go back to the master branch, and bump the minor version to ``0.14.0.dev``.

Building a release
-----------------

1. Create a clean virtual environment of the lowest supported Python version (e.g., 3.9).
2. Check out the release branch and ensure the version number has been updated (no ``.dev`` extension, accurate minor and patch versions).
3. Run ``pip install --upgrade pip wheel build twine`` in order to get the needed release packages.
4. Run ``python -m build`` to build the release.
5. Run ``twine check dist/*`` to check the built artifacts.
6. Run ``twine upload dist/*`` to upload the built artifacts to pypi.
7. Use GitHub releases to draft a new version: tag ``v0.13.0`` and title ``Netconan 0.13.0``. Populate release notes according to recent style and your discretion. Take especial care to acknowledge new or external open source contributions.