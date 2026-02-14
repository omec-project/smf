#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2024 Intel Corporation
#
# Updates aether-onramp configuration files for CI environment
# and configures sd-core values to use local registry image for testing

import argparse
import re
import subprocess
import sys
import tempfile
import shutil
from pathlib import Path
from typing import Dict, Tuple, Optional

try:
    import yaml
except ImportError:
    print("ERROR: PyYAML is required. Install with: sudo apt install python3-yaml", file=sys.stderr)
    sys.exit(1)


def run_command(cmd: list, check: bool = True, capture: bool = True) -> subprocess.CompletedProcess:
    """Run a shell command and return the result."""
    if capture:
        result = subprocess.run(cmd, capture_output=True, text=True, check=check)
    else:
        result = subprocess.run(cmd, check=check)
    return result


def get_network_info() -> Tuple[str, str]:
    """Detect the default network interface and IP address."""
    try:
        # Get default interface
        result = run_command(['ip', 'route'])
        for line in result.stdout.splitlines():
            if 'default' in line:
                parts = line.split()
                interface = parts[parts.index('dev') + 1]
                break
        else:
            raise RuntimeError("Could not find default network interface")
        
        # Get IP address for that interface
        result = run_command(['ip', '-4', 'addr', 'show', interface])
        ip_match = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+)', result.stdout)
        if not ip_match:
            raise RuntimeError(f"Could not find IP address for interface {interface}")
        
        ip_addr = ip_match.group(1)
        return interface, ip_addr
    
    except Exception as e:
        print(f"ERROR: Failed to detect network info: {e}", file=sys.stderr)
        sys.exit(1)


def create_hosts_ini(aether_dir: Path, ip_addr: str) -> None:
    """Create the hosts.ini file for Ansible."""
    hosts_content = f"""[all]
node1 ansible_host={ip_addr} ansible_user=runner ansible_ssh_private_key_file=~/.ssh/id_rsa

[master_nodes]
node1

[worker_nodes]

[gnbsim_nodes]
node1
"""
    hosts_file = aether_dir / 'hosts.ini'
    hosts_file.write_text(hosts_content)
    print(f"Created {hosts_file}")


def update_vars_main(aether_dir: Path, interface: str, ip_addr: str) -> None:
    """Update vars/main.yml with detected interface and IP."""
    vars_file = aether_dir / 'vars' / 'main.yml'
    content = vars_file.read_text()
    
    # Replace interface and IP
    content = content.replace('ens18', interface)
    content = content.replace('10.76.28.113', ip_addr)
    
    vars_file.write_text(content)
    print(f"Updated {vars_file}")


def update_timeouts_and_fixes(aether_dir: Path) -> None:
    """Update various timeout values and apply fixes for CI environment."""
    
    # Update RKE2 install timeouts
    rke2_install = aether_dir / 'deps' / 'k8s' / 'roles' / 'rke2' / 'tasks' / 'install.yml'
    content = rke2_install.read_text()
    content = content.replace('300s', '600s')
    # Remove the deployment wait line that fails in fresh cluster
    content = '\n'.join(line for line in content.splitlines() 
                       if not ('kubectl' in line and 'wait deployment' in line and 'kube-system' in line))
    rke2_install.write_text(content)
    print(f"Updated RKE2 timeouts in {rke2_install}")
    
    # Update 5gc deployment timeouts
    core_install = aether_dir / 'deps' / '5gc' / 'roles' / 'core' / 'tasks' / 'install.yml'
    content = core_install.read_text()
    content = content.replace('--timeout 10m', '--timeout 25m')
    content = content.replace('2m30s', '10m')
    core_install.write_text(content)
    print(f"Updated 5gc timeouts in {core_install}")


def replace_aether_templates_with_placeholders(content: str) -> Tuple[str, Dict[str, str]]:
    """Replace Aether templates {{ ... }} with placeholders."""
    template_pattern = re.compile(r'\{\{[^}]+\}\}')
    templates = {}
    placeholder_index = 0
    
    def replace_template(match):
        nonlocal placeholder_index
        template_text = match.group(0)
        placeholder = f"AETHER_PLACEHOLDER_{placeholder_index}"
        templates[placeholder] = template_text
        placeholder_index += 1
        # Quote the placeholder so YAML parsers treat it as a string
        return f'"{placeholder}"'
    
    modified_content = template_pattern.sub(replace_template, content)
    print(f"Replaced {len(templates)} Aether templates with placeholders", file=sys.stderr)
    return modified_content, templates


def restore_aether_templates(content: str, templates: Dict[str, str]) -> str:
    """Restore Aether templates from placeholders."""
    replacements_made = 0
    
    for placeholder, template in templates.items():
        quoted_placeholder = f'"{placeholder}"'
        
        # Try quoted version first (as inserted), then unquoted (after YAML processing)
        if quoted_placeholder in content:
            content = content.replace(quoted_placeholder, template)
            replacements_made += 1
            print(f"DEBUG: Replaced quoted placeholder {placeholder[:30]}...", file=sys.stderr)
        elif placeholder in content:
            content = content.replace(placeholder, template)
            replacements_made += 1
            print(f"DEBUG: Replaced unquoted placeholder {placeholder[:30]}...", file=sys.stderr)
        else:
            print(f"WARNING: Placeholder not found: {placeholder[:30]}...", file=sys.stderr)
    
    print(f"DEBUG: Made {replacements_made} replacements total", file=sys.stderr)
    return content


def deep_merge_dict(base: dict, override: dict) -> dict:
    """Recursively merge override dict into base dict."""
    result = base.copy()
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = deep_merge_dict(result[key], value)
        else:
            result[key] = value
    return result


def merge_yaml_files(base_file: Path, override_file: Path) -> dict:
    """Merge two YAML files, with override taking precedence."""
    with open(base_file, 'r') as f:
        base = yaml.safe_load(f) or {}
    
    with open(override_file, 'r') as f:
        override = yaml.safe_load(f) or {}
    
    return deep_merge_dict(base, override)


def get_chart_info(aether_dir: Path) -> Tuple[str, str]:
    """Extract Helm chart reference and version from vars/main.yml."""
    vars_file = aether_dir / 'vars' / 'main.yml'
    
    with open(vars_file, 'r') as f:
        vars_data = yaml.safe_load(f)
    
    chart_ref = vars_data.get('core', {}).get('helm', {}).get('chart_ref')
    chart_version = vars_data.get('core', {}).get('helm', {}).get('chart_version')
    
    if not chart_ref or not chart_version:
        print("ERROR: Failed to extract chart information from vars/main.yml", file=sys.stderr)
        print("Expected path: .core.helm.chart_ref and .core.helm.chart_version", file=sys.stderr)
        sys.exit(1)
    
    return chart_ref, chart_version


def find_single_directory(base_dir: Path, name: str) -> Optional[Path]:
    """Find a single directory with the given name, error if multiple or none found."""
    matches = list(base_dir.rglob(name))
    matches = [m for m in matches if m.is_dir()]
    
    if len(matches) == 0:
        return None
    elif len(matches) > 1:
        print(f"ERROR: Found multiple {name} directories:", file=sys.stderr)
        for m in matches:
            print(f"  {m}", file=sys.stderr)
        sys.exit(1)
    
    return matches[0]


def build_image_overrides(
    chart_dir: Path,
    image_name: str,
    local_image_name: str,
    registry_prefix: str
) -> dict:
    """Build the image override structure for sd-core values."""
    overrides = {}
    
    # Process 5g-control-plane images
    control_plane_dir = find_single_directory(chart_dir, '5g-control-plane')
    if control_plane_dir and (control_plane_dir / 'values.yaml').exists():
        with open(control_plane_dir / 'values.yaml', 'r') as f:
            chart_values = yaml.safe_load(f)
        
        tags = {}
        for tag_name, tag_value in chart_values.get('images', {}).get('tags', {}).items():
            if tag_name == image_name:
                print(f"DEBUG: >>> MATCH! Using local image for {tag_name}: {local_image_name}")
                tags[tag_name] = local_image_name
            else:
                print(f"DEBUG: Using registry mirror for {tag_name}: {registry_prefix}{tag_value}")
                tags[tag_name] = f"{registry_prefix}{tag_value}"
        
        overrides['5g-control-plane'] = {
            'images': {
                'repository': '',
                'pullPolicy': 'Always',
                'tags': tags
            }
        }
    
    # Process omec-sub-provision images
    sub_prov_dir = find_single_directory(chart_dir, 'omec-sub-provision')
    if sub_prov_dir and (sub_prov_dir / 'values.yaml').exists():
        print("DEBUG: Adding omec-sub-provision images to overrides...")
        with open(sub_prov_dir / 'values.yaml', 'r') as f:
            chart_values = yaml.safe_load(f)
        
        tags = {}
        for tag_name, tag_value in chart_values.get('images', {}).get('tags', {}).items():
            tags[tag_name] = f"{registry_prefix}{tag_value}"
        
        overrides['omec-sub-provision'] = {
            'images': {
                'repository': '',
                'tags': tags
            }
        }
    
    # Process omec-user-plane images (might be named bess-upf)
    user_plane_dir = find_single_directory(chart_dir, 'omec-user-plane')
    if not user_plane_dir:
        user_plane_dir = find_single_directory(chart_dir, 'bess-upf')
    
    if user_plane_dir and (user_plane_dir / 'values.yaml').exists():
        print("DEBUG: Adding omec-user-plane images to overrides...")
        with open(user_plane_dir / 'values.yaml', 'r') as f:
            chart_values = yaml.safe_load(f)
        
        tags = {}
        for tag_name, tag_value in chart_values.get('images', {}).get('tags', {}).items():
            tags[tag_name] = f"{registry_prefix}{tag_value}"
        
        overrides['omec-user-plane'] = {
            'images': {
                'repository': '',
                'tags': tags
            }
        }
    
    return overrides


def configure_sdcore_images(
    aether_dir: Path,
    image_name: str,
    local_image_name: str
) -> None:
    """Configure sd-core values to use local registry image for testing."""
    print(f"\n=== Configuring {image_name} to use local image ===")
    
    base_values_file = aether_dir / 'deps' / '5gc' / 'roles' / 'core' / 'templates' / 'sdcore-5g-values.yaml'
    registry_prefix = 'registry.aetherproject.org/proxy/'
    
    if not base_values_file.exists():
        print(f"ERROR: Values file does not exist: {base_values_file}", file=sys.stderr)
        sys.exit(1)
    
    print(f"DEBUG: Processing file: {base_values_file}")
    
    # Read original content
    original_content = base_values_file.read_text()
    print(f"DEBUG: Original file size: {len(original_content)} bytes")
    
    # Replace Aether templates with placeholders
    print("Replacing Aether templates with placeholders...")
    modified_content, template_map = replace_aether_templates_with_placeholders(original_content)
    
    # Write modified content to temp file for YAML processing
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as temp_base:
        temp_base.write(modified_content)
        temp_base_path = Path(temp_base.name)
    
    try:
        # Get chart info and pull chart
        chart_ref, chart_version = get_chart_info(aether_dir)
        print(f"Chart: {chart_ref} version {chart_version}")
        
        # Create temp directory for chart
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_chart_dir = Path(temp_dir)
            
            # Pull the Helm chart
            print(f"Pulling Helm chart...")
            run_command(['helm', 'pull', chart_ref, '--version', chart_version, '--untar'],
                       check=True, capture=False)
            
            # Find the pulled chart directory (should be in current directory)
            chart_dirs = [d for d in Path('.').iterdir() if d.is_dir() and d.name.startswith('sd-core')]
            if not chart_dirs:
                print("ERROR: Could not find pulled chart directory", file=sys.stderr)
                sys.exit(1)
            
            pulled_chart_dir = chart_dirs[0]
            
            # Build image overrides
            print("\n=== Extracting image tags from Helm chart values ===")
            overrides = build_image_overrides(
                pulled_chart_dir,
                image_name,
                local_image_name,
                registry_prefix
            )
            
            # Write overrides to temp file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as temp_override:
                yaml.dump(overrides, temp_override, default_flow_style=False, sort_keys=False)
                temp_override_path = Path(temp_override.name)
            
            print("\nDEBUG: Override content:")
            print(temp_override_path.read_text())
            
            try:
                # Merge the YAML files
                print("\nDEBUG: Merging overrides...")
                merged_data = merge_yaml_files(temp_base_path, temp_override_path)
                
                # Write merged data back to string
                merged_yaml = yaml.dump(merged_data, default_flow_style=False, sort_keys=False)
                
                # Restore Aether templates
                print("\nDEBUG: Restoring Aether templates...")
                final_content = restore_aether_templates(merged_yaml, template_map)
                
                # Write final content back to original file
                base_values_file.write_text(final_content)
                
                print(f"\n=== Image overrides merged into: {base_values_file} ===")
                print(f"Local image ({image_name}): {local_image_name}")
                print(f"Other images: {registry_prefix}<image from chart>")
                
            finally:
                temp_override_path.unlink(missing_ok=True)
            
            # Clean up pulled chart
            shutil.rmtree(pulled_chart_dir, ignore_errors=True)
    
    finally:
        temp_base_path.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(
        description='Updates aether-onramp configuration files for CI environment'
    )
    parser.add_argument(
        'aether_onramp_dir',
        type=Path,
        help='Path to aether-onramp directory'
    )
    parser.add_argument(
        'image_name',
        nargs='?',
        help='(optional) Name of image to override in sd-core values'
    )
    parser.add_argument(
        'local_image_name',
        nargs='?',
        help='(optional) Local image tag to use for testing'
    )
    
    args = parser.parse_args()
    
    if not args.aether_onramp_dir.exists():
        print(f"ERROR: Directory does not exist: {args.aether_onramp_dir}", file=sys.stderr)
        sys.exit(1)
    
    # Detect network interface and IP
    interface, ip_addr = get_network_info()
    print(f"Extracted IP: {ip_addr}")
    print(f"Interface: {interface}")
    
    # Update basic aether-onramp configuration
    create_hosts_ini(args.aether_onramp_dir, ip_addr)
    update_vars_main(args.aether_onramp_dir, interface, ip_addr)
    update_timeouts_and_fixes(args.aether_onramp_dir)
    
    print("\nUpdated aether-onramp configuration files")
    
    # Configure sd-core images if parameters provided
    if args.image_name and args.local_image_name:
        configure_sdcore_images(
            args.aether_onramp_dir,
            args.image_name,
            args.local_image_name
        )
    else:
        print("\n=== Skipping sd-core values configuration (IMAGE_NAME and LOCAL_IMAGE_NAME not provided) ===")


if __name__ == '__main__':
    main()
