from jinja2 import Template

def generate_report():
    tpl = Template("Status: {{ status }}")
    return tpl.render(status="ok")
