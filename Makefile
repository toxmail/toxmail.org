.PHONY: docs build test

VIRTUALENV = virtualenv
ifndef VTENV_OPTS
VTENV_OPTS = "--no-site-packages"
endif

build:
	$(VIRTUALENV) $(VTENV_OPTS) .
	bin/pip install --upgrade setuptools
	bin/python setup.py develop
	bin/pip install flake8

test:	bin/nosetests
	bin/nosetests -x toxmailorg
	bin/flake8 toxmailorg

bin/nosetests: bin/python
	bin/pip install nose

