#!/usr/bin/env bash

echo "start content tests"

SECRET_CONF_PATH=$(cat secret_conf_path)
CONF_PATH="./Tests/conf.json"
DEMISTO_API_KEY=$(cat $SECRET_CONF_PATH | jq '.temp_apikey')

temp="${DEMISTO_API_KEY%\"}"
temp="${temp#\"}"
DEMISTO_API_KEY=$temp

[ -n "${MEM_CHECK}" ] && MEM_CHECK=true || MEM_CHECK=false

code_1=0

echo "starting configure_and_install_packs"
PREVIOUS_JOB_NUMBER=`cat create_instances_build_num.txt`

python3 ./Tests/configure_and_install_packs.py -u "$USERNAME" -p "$PASSWORD" -s "$SECRET_CONF_PATH" --ami_env "$1" --branch "$CIRCLE_BRANCH" --build-number "$PREVIOUS_JOB_NUMBER"
code_1=$?

exit $code_1
