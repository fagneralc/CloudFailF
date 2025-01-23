import os
import datetime
import re
from typing import Dict, List, Set, Optional

class ReportGenerator:
    def __init__(self, target: str, found_ips: Dict[str, str], cloudflare_domains: Set[str] = None):
        self.target = target
        self.found_ips = {k.split()[-1]: v for k, v in found_ips.items()}  # Clean domain names
        self.cloudflare_domains = cloudflare_domains if cloudflare_domains else set()
        self.base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.template_dir = os.path.join(self.base_dir, 'util', 'reports')
        self.timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')

    def _get_default_filename(self, extension: str) -> str:
        """Generate default filename based on target and timestamp"""
        return f"cloudfail_{self.target}_{self.timestamp}.{extension}"

    def _read_template(self, template_name: str) -> str:
        """Read template file content"""
        template_path = os.path.join(self.template_dir, template_name)
        try:
            with open(template_path, 'r') as f:
                return f.read()
        except FileNotFoundError:
            raise Exception(f"Template file not found: {template_name}")

    def _process_template(self, content: str, is_markdown: bool = False) -> str:
        """Process template with variables"""
        success_rows = []
        for domain, ip in self.found_ips.items():
            if is_markdown:
                success_rows.append(f"| {ip} | {domain} | Found |")
            else:
                success_rows.append(f"<tr><td>{ip}</td><td>{domain}</td><td>Found</td></tr>")
        
        failed_rows = []
        for domain in self.cloudflare_domains:
            if is_markdown:
                failed_rows.append(f"| N/A | {domain} | CloudFlare Protected |")
            else:
                failed_rows.append(f"<tr><td>N/A</td><td>{domain}</td><td>CloudFlare Protected</td></tr>")

        replacements = {
            "${TARGET}": self.target,
            "${DATE}": datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            "${SUCCESS_ROWS}": "\n".join(success_rows),
            "${FAILED_ROWS}": "\n".join(failed_rows)
        }

        for key, value in replacements.items():
            content = content.replace(key, value)

        return content

    def _ensure_extension(self, path: str, default_ext: str) -> str:
        """Ensure filename has the correct extension"""
        if not path:
            return self._get_default_filename(default_ext)
        
        name, ext = os.path.splitext(path)
        if not ext:
            path = f"{path}.{default_ext}"
        return path

    def generate_html(self, output_path: Optional[str] = None) -> str:
        """Generate HTML report"""
        output_path = self._ensure_extension(output_path, 'html')
        content = self._read_template('template.html')
        processed_content = self._process_template(content)

        with open(output_path, 'w') as f:
            f.write(processed_content)

        return output_path

    def generate_markdown(self, output_path: Optional[str] = None) -> str:
        """Generate Markdown report"""
        output_path = self._ensure_extension(output_path, 'md')
        content = self._read_template('template.md')
        processed_content = self._process_template(content, is_markdown=True)

        with open(output_path, 'w') as f:
            f.write(processed_content)

        return output_path

    def generate_ip_list(self, output_path: Optional[str] = None) -> str:
        """Generate IP list report"""
        if not output_path:
            output_path = self._get_default_filename('txt')
        else:
            base, ext = os.path.splitext(output_path)
            output_path = f"{base}_ips.txt"

        with open(output_path, 'w') as f:
            for ip in sorted(set(self.found_ips.values())):
                f.write(f"{ip}\n")

        return output_path

    def generate_subdomain_list(self, output_path: Optional[str] = None) -> str:
        """Generate subdomain list report"""
        if not output_path:
            output_path = self._get_default_filename('txt')
        else:
            base, ext = os.path.splitext(output_path)
            output_path = f"{base}_subdomains.txt"

        with open(output_path, 'w') as f:
            for domain in sorted(self.found_ips.keys()):
                subdomain = domain.split('.')[0]
                f.write(f"{subdomain}\n")

        return output_path

def generate_report(target: str, found_ips: Dict[str, str], report_types: List[str], 
                   output_path: Optional[str] = None, cloudflare_domains: Set[str] = None) -> List[str]:
    """
    Generate specified report types
    
    Args:
        target: Target domain
        found_ips: Dictionary of found domains and IPs
        report_types: List of report types to generate ('html', 'md', 'ip', 'sub', 'all')
        output_path: Optional output path base
        cloudflare_domains: Optional set of domains protected by CloudFlare
    
    Returns:
        List of generated file paths
    """
    generator = ReportGenerator(target, found_ips, cloudflare_domains)
    generated_files = []

    if 'all' in report_types:
        report_types = ['html', 'md', 'ip', 'sub']
    elif not report_types:
        report_types = ['html', 'ip']

    for report_type in report_types:
        if report_type == 'html':
            generated_files.append(generator.generate_html(output_path))
        elif report_type == 'md':
            generated_files.append(generator.generate_markdown(output_path))
        elif report_type == 'ip':
            generated_files.append(generator.generate_ip_list(output_path))
        elif report_type == 'sub':
            generated_files.append(generator.generate_subdomain_list(output_path))

    return generated_files