# fixture-planted

A deliberately unsafe plugin used by the tests and the Action self-test. Every file here exists to trigger a rule; nothing in it is meant to be installed or run. Secret-shaped strings are not committed: tests/make_secret_fixture.py builds them at run time.
