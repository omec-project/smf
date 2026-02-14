#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2024 Intel Corporation
#
# Updates aether-onramp configuration files for CI environment
# and configures sd-core values to use local registry image for testing

set -e

AETHER_ONRAMP_DIR="${1}"
IMAGE_NAME="${2}"
LOCAL_IMAGE_NAME="${3}"

if [ -z "${AETHER_ONRAMP_DIR}" ]; then
  echo "Usage: $0 <aether-onramp-dir> [image-name] [local-image-name]"
  echo "  aether-onramp-dir: Path to aether-onramp directory"
  echo "  image-name: (optional) Name of image to override in sd-core values"
  echo "  local-image-name: (optional) Local image tag to use for testing"
  exit 1
fi

# Detect network interface and IP address
INTERFACE=$(ip route | awk '/default/ {print $5}')
IP_ADDR=$(ip -4 addr show "${INTERFACE}" | grep -oP '(?<=inet\s)\d+(\.\d+){3}')

if [ -z "${IP_ADDR}" ]; then
  echo "Failed to extract IP address" >&2
  exit 1
fi

echo "Extracted IP: ${IP_ADDR}"
echo "Interface: ${INTERFACE}"

# ==============================================================================
# Update basic aether-onramp configuration (hosts.ini, timeouts)
# ==============================================================================

# Create hosts.ini
cat > "${AETHER_ONRAMP_DIR}/hosts.ini" <<EOF
[all]
node1 ansible_host=${IP_ADDR} ansible_user=runner ansible_ssh_private_key_file=~/.ssh/id_rsa

[master_nodes]
node1

[worker_nodes]

[gnbsim_nodes]
node1
EOF

echo "Created ${AETHER_ONRAMP_DIR}/hosts.ini"

# Update vars/main.yml with detected interface and IP
sed -i "s/ens18/${INTERFACE}/" "${AETHER_ONRAMP_DIR}/vars/main.yml"
sed -i "s/10.76.28.113/${IP_ADDR}/" "${AETHER_ONRAMP_DIR}/vars/main.yml"

# Increase timeouts for CI environment
sed -i "s/300s/600s/" "${AETHER_ONRAMP_DIR}/deps/k8s/roles/rke2/tasks/install.yml"

# Remove the deployment wait line that fails in fresh cluster (no deployments exist yet)
sed -i '/kubectl.*wait deployment.*kube-system/d' "${AETHER_ONRAMP_DIR}/deps/k8s/roles/rke2/tasks/install.yml"

# Increase Helm timeout for 5gc deployment (10m -> 25m)
sed -i "s/--timeout 10m/--timeout 25m/" "${AETHER_ONRAMP_DIR}/deps/5gc/roles/core/tasks/install.yml"
sed -i "s/2m30s/10m/" "${AETHER_ONRAMP_DIR}/deps/5gc/roles/core/tasks/install.yml"

echo "Updated aether-onramp configuration files"

echo hosts.ini content:
cat "${AETHER_ONRAMP_DIR}/hosts.ini"

echo "Updated vars/main.yml content (interface and IP):"
cat "${AETHER_ONRAMP_DIR}/vars/main.yml"

echo "Updated RKE2 install.yml content (timeouts):"
cat "${AETHER_ONRAMP_DIR}/deps/k8s/roles/rke2/tasks/install.yml"

echo "Updated 5gc install.yml content (Helm timeout):"
cat "${AETHER_ONRAMP_DIR}/deps/5gc/roles/core/tasks/install.yml"

# ==============================================================================
# Configure sd-core values to use local registry image (if parameters provided)
# ==============================================================================

if [ -n "${IMAGE_NAME}" ] && [ -n "${LOCAL_IMAGE_NAME}" ]; then
  echo ""
  echo "=== Configuring ${IMAGE_NAME} to use local image ==="

  BASE_VALUES_FILE="${AETHER_ONRAMP_DIR}/deps/5gc/roles/core/templates/sdcore-5g-values.yaml"
  REGISTRY_PREFIX="registry.aetherproject.org/proxy/"
  CI_MARKER="# === CI/CD OVERRIDES START - DO NOT EDIT BELOW THIS LINE ==="

  # Check if file exists
  if [ ! -f "${BASE_VALUES_FILE}" ]; then
    echo "ERROR: Values file does not exist: ${BASE_VALUES_FILE}"
    echo "Listing directory contents:"
    ls -la "$(dirname "${BASE_VALUES_FILE}")" || echo "Directory does not exist"
    exit 1
  fi

  echo "DEBUG: File exists, size: $(wc -c < "${BASE_VALUES_FILE}") bytes"
  echo "DEBUG: Original file content:"
  cat "${BASE_VALUES_FILE}"
  echo ""
  echo "DEBUG: ===================="
  echo ""

  # Save original file as backup
  cp "${BASE_VALUES_FILE}" "${BASE_VALUES_FILE}.original"

  # Replace Jinja2 templates with placeholders to make YAML parseable
  echo "Replacing Jinja2 templates with placeholders..."
  TEMPLATE_MAP=$(mktemp)
  PLACEHOLDER_INDEX=0

  # Read file line by line and replace {{ ... }} with __JINJA_PLACEHOLDER_N__
  python3 <<PYREPLACE
import re
import sys

input_file = "${BASE_VALUES_FILE}.original"
output_file = "${BASE_VALUES_FILE}"
map_file = "${TEMPLATE_MAP}"

with open(input_file, 'r') as f:
    content = f.read()

# Find all Jinja2 template expressions
template_pattern = re.compile(r'\{\{[^}]+\}\}')
templates = {}
placeholder_index = 0

def replace_template(match):
    global placeholder_index
    template_text = match.group(0)
    placeholder = f"__JINJA_PLACEHOLDER_{placeholder_index}__"
    templates[placeholder] = template_text
    placeholder_index += 1
    return f'"{placeholder}"'

# Replace all templates with placeholders
modified_content = template_pattern.sub(replace_template, content)

# Write modified content
with open(output_file, 'w') as f:
    f.write(modified_content)

# Write mapping file (no escaping needed since Python will restore, not sed)
with open(map_file, 'w') as f:
    for placeholder, template in templates.items():
        f.write(f"{placeholder}|||{template}\n")

print(f"Replaced {len(templates)} Jinja2 templates with placeholders", file=sys.stderr)
PYREPLACE

  echo "DEBUG: After replacing Jinja2 templates:"
  cat "${BASE_VALUES_FILE}"
  echo ""
  echo "DEBUG: Template mapping:"
  cat "${TEMPLATE_MAP}"

  # Fetch the Helm chart to extract default image tags dynamically
  CHART_REF=$(yq -r '.core.helm.chart_ref' "${AETHER_ONRAMP_DIR}/vars/main.yml")
  CHART_VERSION=$(yq -r '.core.helm.chart_version' "${AETHER_ONRAMP_DIR}/vars/main.yml")

  if [ -z "${CHART_REF}" ] || [ "${CHART_REF}" = "null" ] || [ -z "${CHART_VERSION}" ] || [ "${CHART_VERSION}" = "null" ]; then
    echo "ERROR: Failed to extract chart information from vars/main.yml"
    echo "Expected path: .core.helm.chart_ref and .core.helm.chart_version"
    echo "Dumping vars/main.yml structure for debugging:"
    yq '.' "${AETHER_ONRAMP_DIR}/vars/main.yml" | head -50
    exit 1
  fi

  echo "Chart: ${CHART_REF} version ${CHART_VERSION}"

  # Create temp directory and pull the chart
  TEMP_DIR=$(mktemp -d)
  trap 'rm -rf "${TEMP_DIR}"' EXIT

  cd "${TEMP_DIR}"
  helm pull "${CHART_REF}" --version "${CHART_VERSION}" --untar

  # Find the subcharts - validate exactly one match exists
  CHART_MATCHES=$(find . -name "5g-control-plane" -type d | sort)
  CHART_COUNT=$(echo "${CHART_MATCHES}" | grep -c . || true)
  if [ "${CHART_COUNT}" -eq 0 ]; then
    echo "ERROR: Could not find 5g-control-plane chart"
    exit 1
  elif [ "${CHART_COUNT}" -gt 1 ]; then
    echo "ERROR: Found multiple 5g-control-plane directories:"
    echo "${CHART_MATCHES}"
    exit 1
  fi
  CHART_DIR=$(echo "${CHART_MATCHES}" | head -1)

  echo "=== Extracting image tags from Helm chart values ==="
  echo "DEBUG: IMAGE_NAME to override: '${IMAGE_NAME}'"
  echo "DEBUG: LOCAL_IMAGE_NAME: '${LOCAL_IMAGE_NAME}'"
  echo "DEBUG: Chart values file: ${CHART_DIR}/values.yaml"
  echo "DEBUG: Available tags in chart:"
  yq -r '.images.tags | keys | .[]' "${CHART_DIR}/values.yaml"
  echo ""

  # Build override YAML with proper structure
  OVERRIDE_FILE=$(mktemp)
  echo "DEBUG: Building override YAML..."
  cat > "${OVERRIDE_FILE}" <<EOF
5g-control-plane:
  images:
    repository: ""
    pullPolicy: Always
    tags:
EOF

  # Extract each tag from the chart values and add to override file
  for tag_name in $(yq -r '.images.tags | keys | .[]' "${CHART_DIR}/values.yaml"); do
    tag_value=$(yq -r ".images.tags.${tag_name}" "${CHART_DIR}/values.yaml")
    echo "DEBUG: Processing tag '${tag_name}' = '${tag_value}'"
    if [ "${tag_name}" = "${IMAGE_NAME}" ]; then
      # Use local image for the one being tested
      echo "DEBUG: >>> MATCH! Using local image: ${LOCAL_IMAGE_NAME}"
      echo "      ${tag_name}: \"${LOCAL_IMAGE_NAME}\"" >> "${OVERRIDE_FILE}"
    else
      # Use registry mirror for all others
      echo "DEBUG: Using registry mirror: ${REGISTRY_PREFIX}${tag_value}"
      echo "      ${tag_name}: \"${REGISTRY_PREFIX}${tag_value}\"" >> "${OVERRIDE_FILE}"
    fi
  done

  echo "DEBUG: Completed 5g-control-plane section"

  # Handle omec-sub-provision images
  SUB_PROV_MATCHES=$(find . -name "omec-sub-provision" -type d | sort)
  SUB_PROV_COUNT=$(echo "${SUB_PROV_MATCHES}" | grep -c . || true)
  if [ "${SUB_PROV_COUNT}" -gt 1 ]; then
    echo "ERROR: Found multiple omec-sub-provision directories:"
    echo "${SUB_PROV_MATCHES}"
    exit 1
  fi
  SUB_PROV_DIR=$(echo "${SUB_PROV_MATCHES}" | head -1)
  if [ -n "$SUB_PROV_DIR" ] && [ -f "${SUB_PROV_DIR}/values.yaml" ]; then
    echo "DEBUG: Adding omec-sub-provision images to overrides..."
    cat >> "${OVERRIDE_FILE}" <<EOF

omec-sub-provision:
  images:
    repository: ""
    tags:
EOF
    for tag_name in $(yq -r '.images.tags | keys | .[]' "${SUB_PROV_DIR}/values.yaml" 2>/dev/null || echo ""); do
      tag_value=$(yq -r ".images.tags.${tag_name}" "${SUB_PROV_DIR}/values.yaml")
      echo "      ${tag_name}: \"${REGISTRY_PREFIX}${tag_value}\"" >> "${OVERRIDE_FILE}"
    done
  fi

  # Handle omec-user-plane images
  USER_PLANE_MATCHES=$(find . -name "omec-user-plane" -type d -o -name "bess-upf" -type d | sort)
  USER_PLANE_COUNT=$(echo "${USER_PLANE_MATCHES}" | grep -c . || true)
  if [ "${USER_PLANE_COUNT}" -gt 1 ]; then
    echo "ERROR: Found multiple user-plane directories:"
    echo "${USER_PLANE_MATCHES}"
    exit 1
  fi
  USER_PLANE_DIR=$(echo "${USER_PLANE_MATCHES}" | head -1)
  if [ -n "$USER_PLANE_DIR" ] && [ -f "${USER_PLANE_DIR}/values.yaml" ]; then
    echo "DEBUG: Adding omec-user-plane images to overrides..."
    cat >> "${OVERRIDE_FILE}" <<EOF

omec-user-plane:
  images:
    repository: ""
    tags:
EOF
    for tag_name in $(yq -r '.images.tags | keys | .[]' "${USER_PLANE_DIR}/values.yaml" 2>/dev/null || echo ""); do
      tag_value=$(yq -r ".images.tags.${tag_name}" "${USER_PLANE_DIR}/values.yaml")
      echo "      ${tag_name}: \"${REGISTRY_PREFIX}${tag_value}\"" >> "${OVERRIDE_FILE}"
    done
  fi

  echo "DEBUG: Override file content:"
  cat "${OVERRIDE_FILE}"
  echo ""

  # Merge overrides into base values using yq (now that Jinja2 templates are replaced)
  echo "DEBUG: Merging overrides using yq..."
  MERGED_FILE=$(mktemp)
  if yq merge -x "${BASE_VALUES_FILE}" "${OVERRIDE_FILE}" > "${MERGED_FILE}" 2>/dev/null; then
    echo "DEBUG: Used yq merge (v3)"
    mv "${MERGED_FILE}" "${BASE_VALUES_FILE}"
  elif yq eval-all 'select(fileIndex == 0) * select(fileIndex == 1)' "${BASE_VALUES_FILE}" "${OVERRIDE_FILE}" > "${MERGED_FILE}" 2>/dev/null; then
    echo "DEBUG: Used yq eval-all (v4)"
    mv "${MERGED_FILE}" "${BASE_VALUES_FILE}"
  else
    echo "ERROR: yq merge failed, trying Python fallback..."
    python3 <<PYMERGE
import yaml
import sys

try:
    with open("${BASE_VALUES_FILE}", 'r') as f:
        base = yaml.safe_load(f) or {}
    with open("${OVERRIDE_FILE}", 'r') as f:
        override = yaml.safe_load(f) or {}

    # Deep merge function
    def merge_dict(base_dict, override_dict):
        for key, value in override_dict.items():
            if key in base_dict and isinstance(base_dict[key], dict) and isinstance(value, dict):
                merge_dict(base_dict[key], value)
            else:
                base_dict[key] = value

    merge_dict(base, override)

    with open("${BASE_VALUES_FILE}", 'w') as f:
        yaml.dump(base, f, default_flow_style=False, sort_keys=False)
    print("DEBUG: Python merge completed", file=sys.stderr)
except Exception as e:
    print(f"ERROR: Merge failed: {e}", file=sys.stderr)
    sys.exit(1)
PYMERGE
  fi

  rm -f "${OVERRIDE_FILE}" "${MERGED_FILE}"

  # Restore Jinja2 templates from placeholders using Python (handles special chars properly)
  echo "DEBUG: Restoring Jinja2 templates..."
  echo "DEBUG: Template map file: ${TEMPLATE_MAP}"
  echo "DEBUG: Template map contents:"
  cat "${TEMPLATE_MAP}"
  echo ""
  
  python3 <<PYRESTORE
import sys

values_file = "${BASE_VALUES_FILE}"
map_file = "${TEMPLATE_MAP}"

# Read the merged values file
with open(values_file, 'r') as f:
    content = f.read()

print(f"DEBUG: Original content length: {len(content)}", file=sys.stderr)

# Read the mapping and restore templates
replacements_made = 0
with open(map_file, 'r') as f:
    for line in f:
        line = line.strip()
        if '|||' in line:
            placeholder, template = line.split('|||', 1)
            # Try both quoted and unquoted versions
            quoted_placeholder = f'"{placeholder}"'
            
            if quoted_placeholder in content:
                print(f"DEBUG: Replacing quoted: {quoted_placeholder[:50]}...", file=sys.stderr)
                content = content.replace(quoted_placeholder, template)
                replacements_made += 1
            elif placeholder in content:
                print(f"DEBUG: Replacing unquoted: {placeholder[:50]}...", file=sys.stderr)
                content = content.replace(placeholder, template)
                replacements_made += 1
            else:
                print(f"DEBUG: Placeholder not found: {placeholder[:50]}...", file=sys.stderr)

print(f"DEBUG: Made {replacements_made} replacements", file=sys.stderr)
print(f"DEBUG: Final content length: {len(content)}", file=sys.stderr)

# Write back the restored content
with open(values_file, 'w') as f:
    f.write(content)

print("DEBUG: Restored Jinja2 templates", file=sys.stderr)
PYRESTORE
  
  echo "DEBUG: After restoring Jinja2 templates:"
  head -50 "${BASE_VALUES_FILE}"
  
  rm -f "${TEMPLATE_MAP}" "${BASE_VALUES_FILE}.original"

  # Return to original directory (TEMP_DIR cleanup handled by trap)
  cd -

  echo "=== Summary of image configuration ==="
  echo "Local image (${IMAGE_NAME}): ${LOCAL_IMAGE_NAME}"
  echo "Other images: ${REGISTRY_PREFIX}<image from chart>"
  echo ""
  echo "=== Image overrides merged into: ${BASE_VALUES_FILE} ==="
  cat "${BASE_VALUES_FILE}"
else
  echo ""
  echo "=== Skipping sd-core values configuration (IMAGE_NAME and LOCAL_IMAGE_NAME not provided) ==="
fi
