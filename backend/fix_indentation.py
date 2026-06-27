import re

with open('api_server.py', 'r') as f:
    content = f.read()

# Find and fix the run_pipeline function
# The function should be properly indented under the @app.post decorator
lines = content.split('\n')
fixed_lines = []
in_run_pipeline = False
indent_level = 0

for i, line in enumerate(lines):
    if '@app.post("/api/settings/run-pipeline")' in line:
        in_run_pipeline = True
        fixed_lines.append(line)
        continue
    if in_run_pipeline:
        if line.strip() == '':
            fixed_lines.append(line)
            continue
        if line.strip().startswith('async def run_pipeline'):
            fixed_lines.append('    ' + line.lstrip())
            continue
        if line.strip().startswith('try:'):
            fixed_lines.append('        ' + line.lstrip())
            continue
        if line.strip().startswith('result = subprocess.run'):
            fixed_lines.append('            ' + line.lstrip())
            continue
        if line.strip().startswith('[sys.executable'):
            fixed_lines.append('            ' + line.lstrip())
            continue
        if line.strip().startswith('cwd='):
            fixed_lines.append('            ' + line.lstrip())
            continue
        if line.strip().startswith('capture_output='):
            fixed_lines.append('            ' + line.lstrip())
            continue
        if line.strip().startswith('text='):
            fixed_lines.append('            ' + line.lstrip())
            continue
        if line.strip().startswith('timeout='):
            fixed_lines.append('            ' + line.lstrip())
            continue
        if line.strip().startswith('return {'):
            fixed_lines.append('            ' + line.lstrip())
            continue
        if line.strip().startswith('"status"'):
            fixed_lines.append('                ' + line.lstrip())
            continue
        if line.strip().startswith('"output"'):
            fixed_lines.append('                ' + line.lstrip())
            continue
        if line.strip().startswith('except'):
            fixed_lines.append('        ' + line.lstrip())
            continue
        if line.strip().startswith('return'):
            fixed_lines.append('        ' + line.lstrip())
            continue
        if line.strip().startswith('@app.'):
            in_run_pipeline = False
            fixed_lines.append(line)
            continue
    fixed_lines.append(line)

# Write the fixed content
with open('api_server_fixed.py', 'w') as f:
    f.write('\n'.join(fixed_lines))

print("Fixed api_server.py written to api_server_fixed.py")
