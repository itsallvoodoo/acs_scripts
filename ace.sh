#! /bin/bash


echo "    #     #####   #####      #####  #     # #######    #######                                                 "
echo "   # #   #     # #     #    #     # #     # #          #       #    # #####   ####  #####  ##### ###### #####  "
echo "  #   #  #       #          #       #     # #          #        #  #  #    # #    # #    #   #   #      #    # "
echo " #     # #        #####     #       #     # #####      #####     ##   #    # #    # #    #   #   #####  #    # "
echo " ####### #             #    #        #   #  #          #         ##   #####  #    # #####    #   #      #####  "
echo " #     # #     # #     #    #     #   # #   #          #        #  #  #      #    # #   #    #   #      #   #  "
echo " #     #  #####   #####      #####     #    #######    ####### #    # #       ####  #    #   #   ###### #    # "
                                                                                                               
echo ""
echo "The purpose of this script is to export cve data from Red Hat Advanced Cluster Security into a csv file, including all deployments and images"
echo "export ACS_ENDPOINT=central-stackrox.apps.vapo-XXX.va.gov"
echo "export ACS_API_TOKEN=`curl -sk -u "admin:PASSWORD" "https://${ACS_ENDPOINT}/v1/apitokens/generate" -d '{"name":"token name", "role": "Admin"}' | jq -r '.token'`
echo "export CVSS_VALUE=7"
echo "./ace.sh test.csv"
echo "

set -e

if command jq --version >/dev/null 2>$1 ; then
  echo "Dependency check passed"
else
  echo "Please install jq, a json parsing package, for your system."
  exit 1
fi


if [[ -z "${ACS_ENDPOINT}" ]]; then
  echo >&2 "A URL to access, stored in the environment variable ACS_ENDPOINT, must be set. Use format sub.domain.com, not including https:// nor /v1..."
  exit 1
else
  echo "ACS_ENDPOINT variable check passed"
fi

if [[ -z "${ACS_API_TOKEN}" ]]; then
  echo >&2 "An API Token, stored in the environment variable ACS_API_TOKEN, must be set. It must have read permissions for alerts, deployments, and images."
  exit 1
else
  echo "ACS_API_TOKEN variable check passed"
fi

if [[ -z "$1" ]]; then
  echo >&2 "Please supply a blank (or existing) csv filename as the first argument for the bash script, ie: './ace.sh output.csv'"
  exit 1
else
  echo "Export CSV check passed"
fi

if [[ -z "${CVSS_VALUE}" ]]; then
  echo >&2 "A minimum CVSS_VALUE score for filtering, stored in the environment variable CVSS, must be set. It can range from 0 to 10."
  exit 1
else
  echo "CVSS_VALUE variable check passed"
fi

output_file="$1"
echo '"Deployment", "Image", "CVE", "CVSS Score", "Summary", "Component", "Version", "Fixed By", "Layer Index", "Layer Instruction"' > "${output_file}"

function curl_central() {
  curl -sk -H "Authorization: Bearer ${ACS_API_TOKEN}" "https://${ACS_ENDPOINT}/$1"
}

# Looking into ways to adjust granularity of reporting via different queries. Currently just gets all
#res="$(curl_central "v1/alerts?query=Policy%3AFixable%20CVSS%20%3E%3D%20${cvss}")"
res="$(curl_central "v1/alerts")"

# API access error handling
test="$(echo ${res})"
if [[ $test == *"error"* ]] ; then
  echo "There was an error accessing the API."
  echo "The error message was: $(echo ${test} | jq '.error')."
  echo "Please address this access issue and retry."
  exit 1
fi

# Collect all alerts
cvss=${CVSS_VALUE}
echo "Getting findings with a CVSS score of ${cvss} or greater. This may take a few minutes, depending on number of findings."

# Iterate over all deployments and get the full deployment
for deployment_id in $(echo "${res}" | jq -r .alerts[].deployment.id); do
  deployment_res="$(curl_central "v1/deployments/${deployment_id}")"
  if [[ "$(echo "${deployment_res}" | jq -rc .name)" == null ]]; then
   continue;
  fi
  
  if [[ "$(echo "${deployment_res}" | jq '.containers | length')" == "0" ]]; then
   continue;
  fi

  deployment_name="$(echo "${deployment_res}" | jq -rc .name)"
  export deployment_name
    
   # Iterate over all images within the deployment and render the CSV Lines
   for image_id in $(echo "${deployment_res}" | jq -r 'select(.containers != null) | .containers[].image.id'); do
     if [[ "${image_id}" != "" ]]; then
       image_res="$(curl_central "v1/images/${image_id}" | jq -rc)" 
       if [[ "$(echo "${image_res}" | jq -rc .name)" == null ]]; then
        continue;
       fi

       image_name="$(echo "${image_res}" | jq -rc '.name.fullName')"
       export image_name
       
       # Format the CSV correctly
       echo "${image_res}" | jq -r --argjson cvss "$cvss" 'try (.metadata.v1.layers as $layers | .scan.components | sort_by(.layerIndex, .name) | .[]? | . as $component | select(.vulns != null) | .vulns[] | select(.cvss >= $cvss) | select(.fixedBy != null) | [ env.deployment_name, env.image_name, .cve, .cvss, .summary, $component.name, $component.version, .fixedBy, $component.layerIndex, ($layers[$component.layerIndex // 0].instruction + " " +$layers[$component.layerIndex // 0].value)]) | @csv' >> "${output_file}"
     fi
   done
  done

{"error":"not authorized: \"READ_ACCESS\" for \"Alert\"","code":7,"message":"not authorized: \"READ_ACCESS\" for \"Alert\"","details":[]}
