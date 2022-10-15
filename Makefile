export SHELL
SHELL:=/bin/bash
ROOT_DIR:=$(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))
EMAIL:=
INSTANCE_TYPE:=ml.t2.medium
BRANCH:=main

AFA_STACK_NAME:=AfaStack
BOOTSTRAP_STACK_NAME:=AfaBootstrapStack
CDK_TAGS:=--tags Project=Afa

.PHONY: deploy tests default release

default: .venv

# create the virtual environment from which to run each target
.venv: requirements.txt
	python3 -B -m venv $@
	source $@/bin/activate ; pip install -q --use-deprecated=legacy-resolver -r $<

.tox: requirements.txt
	tox -r --notest

tests/reports:
	mkdir -p $@

tox: tests/reports .tox
	tox

tests: .venv
	source $</bin/activate ; \
	pytest -vs tests/

build/:
	mkdir -p $@

build/template.yaml: cdk/app.py cdk/cdk/bootstrap.py build/
	cdk synth -a 'python3 -B $<' -c branch=${BRANCH} ${BOOTSTRAP_STACK_NAME} > $@

build/build.zip:
	zip -r $< build

# Deploy the bootstrap stack
deploy: build/template.yaml .venv
	source $(word 2, $^)/bin/activate ; \
	aws cloudformation deploy \
		--template-file $< \
		--capabilities CAPABILITY_NAMED_IAM \
		--stack-name ${BOOTSTRAP_STACK_NAME} \
		--parameter-overrides \
			emailAddress=${EMAIL} \
			instanceType=${INSTANCE_TYPE} \
		${CDK_TAGS}

# Deploy the ui stack
deploy-ui: cdk/app.py .venv
	source $(word 2, $^)/bin/activate ; \
	cdk deploy -a 'python3 -B $<' ${AFA_STACK_NAME} \
		--require-approval never \
		--parameters ${AFA_STACK_NAME}:emailAddress=${EMAIL} \
		--parameters ${AFA_STACK_NAME}:instanceType=${INSTANCE_TYPE} \
		${CDK_TAGS}
