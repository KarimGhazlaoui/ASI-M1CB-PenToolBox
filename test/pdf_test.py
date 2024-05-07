from jinja2 import Environment, FileSystemLoader
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph
from io import BytesIO
import pdfkit

# Step 2: Load template
env = Environment(loader=FileSystemLoader('.'))
template = env.get_template('template.html')

# Step 3: Render template with variables
data = {
    'title': 'Penetration Test Report',
    'logo_path': 'path/to/logo.png',
    'content': 'This is the content of your report.'
}
html_content = template.render(data)

# Step 4: Convert HTML to PDF
pdf_output = BytesIO()
pdfkit.from_string(html_content, pdf_output)  # You can also use ReportLab here for more control over PDF generation

# Save PDF to a file
with open('penetration_test_report.pdf', 'wb') as f:
    f.write(pdf_output.getvalue())
