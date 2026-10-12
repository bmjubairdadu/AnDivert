# Contributing to AnDivert

Thanks for your interest! AnDivert is a young project and every kind of
contribution helps: bug reports, documentation, tests, and code.

## Ground rules

AnDivert is a **networking tool**. Contributions must serve legitimate
uses: firewalls, DNS filtering, traffic monitoring, VPN/tunneling,
privacy tools, and debugging.

**Will not be accepted:** anything whose primary purpose is cheating in
online games (lag switching / packet holding against game servers),
attacking, surveilling, or disrupting other people or services. This is
a condition of the project, not a stylistic preference.

## Reporting bugs

Open an issue with:

1. Device model + Android version
2. The filter expression you used
3. `AnDivert.stats()` output and the relevant logcat lines
   (`adb logcat -s AnDivert:*`)
4. What you expected vs. what happened

For crashes, include the full stack trace.

## Development setup

```bash
git clone https://github.com/bmjubairdadu/AnDivert.git

# native engine + live tests — any Linux or WSL:
bash tools/ci_build_and_test.sh          # needs gcc; JAVA_HOME if jni.h available

# Android AAR — needs Android SDK + NDK 26.3:
./gradlew :andivert:assembleRelease
```

The live test suite (`andivert/test/ad_test.c`) must pass 29/29 before any
PR. If you change packet handling, add a test that proves the change.

## Code style

- C: C99, 4-space indent, no tabs, matching the existing files
- Kotlin: standard ktlint style, documented public API
- Every public API change updates README's API table and CHANGELOG.md

## Pull requests

1. Fork, create a branch (`feat/my-change`)
2. Make the change with tests
3. `bash tools/ci_build_and_test.sh` must pass
4. CI must be green on your branch
5. Describe *why*, not only *what*

## Releasing (maintainers)

1. Update `CHANGELOG.md`
2. Tag: `git tag v1.x.y && git push origin v1.x.y`
3. CI builds the AAR and publishes the release automatically
