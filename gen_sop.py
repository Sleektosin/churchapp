"""Generate the SOP Word (.docx) document for the Church Management System.

Dependency-free: builds a valid OOXML .docx with the standard library only.
"""
import zipfile
from xml.sax.saxutils import escape

OUT = "SOP_RCCG_PowerHouse_Church_Management_System.docx"

# ---------------------------------------------------------------- content
# Each block: ('title'|'h1'|'h2'|'h3'|'p'|'bullet'|'spacer', text)
blocks = []
def title(t): blocks.append(('title', t))
def sub(t): blocks.append(('subtitle', t))
def h1(t): blocks.append(('h1', t))
def h2(t): blocks.append(('h2', t))
def p(t): blocks.append(('p', t))
def b(t): blocks.append(('bullet', t))
def spacer(): blocks.append(('spacer', ''))

title("Standard Operating Procedure (SOP)")
sub("RCCG Power House Parish – Church Management System")
p("Document purpose: This SOP explains, in plain language, what every section of the "
  "Church Management System does and how to use it. It is intended for administrators, "
  "ushers/attendance officers, and members so that anyone can understand and operate the "
  "platform with confidence.")
p("Version: 1.0    |    Audience: Administrators, Attendance Officers, Members")
spacer()

h1("1. System Overview")
p("The Church Management System is a web application for managing a congregation's members, "
  "worship/attendance sessions, church assets (inventory), and reporting. It provides secure "
  "sign-in, role-based access control, multiple attendance check-in methods (including "
  "fingerprint/biometric), an analytics dashboard, and a public landing page with a live-stream "
  "section.")
p("The application is organised into a public website (the landing/home page) and a secured "
  "admin area reached after login. The left sidebar is the primary navigation for the admin area; "
  "a Back button and a Home button are available in the top header on every admin page.")

h1("2. User Roles and Access Control (RBAC)")
p("Access to features is controlled by Role-Based Access Control (RBAC). Every user is assigned "
  "one or more roles, and each role grants a set of permissions. The menu items and pages a user "
  "can see depend entirely on the permissions their roles grant.")
h2("2.1 Default Roles")
b("Admin – full administrative access to every feature.")
b("User – standard member access (dashboard view and self check-in).")
b("Guest – limited, read-only access.")
h2("2.2 Permissions")
p("Permissions are fine-grained capabilities such as: Manage Users, Manage Sessions, Manage "
  "Inventory, Manage Maintenance, View Analytics, Manage Biometrics, Reset Passwords, Reset "
  "Emails, and Manage Roles. The Admin role always holds every permission and cannot be locked out.")
h2("2.3 Roles & Permissions Page (Admin)")
p("Found under Administration > Roles. Administrators can create new roles, edit a role's name "
  "and description, and tick exactly which permissions each role grants. Core roles (Admin, User, "
  "Guest) cannot be renamed or deleted. Assigning a permission to a role immediately changes what "
  "users with that role can access – no technical change is required.")
h2("2.4 Assigning Roles to Users")
p("Roles are assigned per user in two places: (a) on the user's Profile page under ‘Roles & "
  "Access’, and (b) directly from the Manage Users table using the quick-edit (pencil) button "
  "in the Roles column. Safeguards prevent an administrator from removing their own Admin role or "
  "deleting the last remaining administrator.")

h1("3. Signing In and Account Security")
h2("3.1 Login")
p("Users sign in with their email and password. After a successful login, members are taken to "
  "the Home area and administrators to the Sessions area.")
h2("3.2 Idle Auto-Logout")
p("For security, a user who stays inactive for a period of time is automatically signed out and "
  "must log in again. This protects accounts left open on shared devices.")
h2("3.3 Forgot / Reset Password (Self-service)")
p("On the login page, ‘Forgot Password’ starts a secure reset: the user enters their email; "
  "if an account exists, a one-time reset code is emailed to them; they then enter the code and "
  "choose a new password. The code expires after a short period.")
h2("3.4 Administrator-assisted Reset")
p("From a user's Profile page, an administrator can reset that user's password or change their "
  "email address (for example, to help a member who is locked out).")

h1("4. Home / Landing Page")
p("The public Home page introduces the church (about, services, events, gallery, contact) and "
  "includes a dedicated ‘Live Sessions’ section.")
h2("4.1 Live Sessions Feed")
p("The Live Sessions section embeds the church's Facebook page feed so that live broadcasts and "
  "recent posts appear directly on the website, alongside quick links to open Facebook or "
  "Instagram. When the church goes live on Facebook, the stream is visible here. (The Facebook "
  "page and Instagram links are configurable by the administrator.)")

h1("5. Navigation, Back Button and Breadcrumbs")
b("Sidebar – the main menu on the left; only shows the sections the signed-in user is "
  "permitted to access.")
b("Back button – the left-arrow button in the top header returns the user to the previous "
  "page; if there is no previous page it goes Home.")
b("Home button – the house icon in the top header returns the user to the Home page.")
b("Breadcrumbs – the small trail at the top of each page (for example ‘Home / Inventory’) "
  "shows where the user is; the first link always returns to Home.")

h1("6. Sessions Management")
p("A ‘session’ is a service, meeting, or event for which attendance is recorded. The Sessions "
  "page (Admin) lists all sessions and lets administrators create, edit, and delete them.")
h2("6.1 Creating a Session")
p("When creating a session the administrator provides a name, description, date, start/end time, "
  "location, capacity, and check-in window. A unique QR code is generated automatically for the "
  "session. The session date cannot be set in the past – the system rejects past dates with an "
  "error.")
h2("6.2 Session Status")
p("Each session has a status (scheduled, active, completed, or cancelled). Once a session is "
  "marked Completed, users can no longer be added to it through any check-in method.")

h1("7. Adding Members to a Session (Attendance Check-in)")
p("There are three ways a member can be recorded as present in a session. The session view shows "
  "an ‘Added Via’ column indicating, for each member, exactly how they were checked in.")
h2("7.1 Biometric (Fingerprint)")
p("A member who has enrolled a fingerprint can check in by scanning their finger. The system "
  "matches the fingerprint to the member and adds them to the session. Recorded as ‘Biometric’.")
h2("7.2 Scanning the Member's Barcode")
p("An attendance officer scans the member's personal QR/barcode (from their profile) to add them. "
  "Recorded as ‘User Barcode’.")
h2("7.3 Member Scans the Session Barcode")
p("A member scans the session's QR code, then identifies themselves to complete a self check-in. "
  "Recorded as ‘Session QR’.")
p("In all three methods, attempting to add a member to a Completed session is blocked with a clear "
  "message.")

h1("8. Biometric (Fingerprint) Management")
p("Biometrics let members check in quickly and securely using device fingerprint hardware "
  "(WebAuthn). Enrolment and removal are managed by administrators.")
h2("8.1 Enrolling a Fingerprint")
p("From the Manage Users table, an administrator opens the fingerprint enrolment page for a member "
  "and the member scans their finger on the device. A member can enrol on more than one device.")
h2("8.2 Viewing and Removing Enrolled Devices")
p("In the Manage Users table, the Biometric column shows whether a member is enrolled and on how "
  "many devices. The Manage (gear) button opens a dialog listing each enrolled device with a "
  "Remove option, so an administrator can de-enrol a fingerprint from a specific device.")

h1("9. Manage Users")
p("The Manage Users page (Administration) is the central directory of members. It is a searchable, "
  "sortable, paginated table.")
b("View / add / edit / delete members.")
b("Roles column – see each member's roles and quick-edit them.")
b("Biometric column – see enrolment status and manage fingerprint devices.")
b("Actions – view the full profile, edit details, enrol fingerprint, or delete the member.")

h1("10. User Profile")
p("Each member has a Profile page showing their personal information, attendance statistics, "
  "personal QR code (downloadable), and recent activity. For administrators, the profile also "
  "provides account-management tools: Reset Password, Reset Email, manage fingerprint devices, and "
  "assign/revoke Roles.")

h1("11. Inventory")
p("The Inventory area (Resources) tracks church assets and their upkeep. It has three parts.")
h2("11.1 Items (Assets)")
p("A catalogue of every asset (name, manufacturer, model, custodian unit, purchase date, quantity, "
  "value). Administrators can add, edit, and delete items.")
h2("11.2 Maintenance")
p("A history of maintenance performed on items (date, vendor, description, cost). Used to keep "
  "assets serviceable and to track spending.")
h2("11.3 Inventories (Stock Overview)")
p("A consolidated stock view with summary cards (distinct items, total units, total value, low "
  "stock, out of stock) and a filterable table. Standard filters include category, stock status "
  "(In Stock / Low Stock / Out of Stock), and purchase-date range. Each row shows the item's "
  "quantity, value, stock status, and last maintenance date.")

h1("12. Analytics Dashboard")
p("The Analytics page (Resources) presents key performance indicators (KPIs) and charts for "
  "decision-making. A date-range filter at the top controls the period analysed, with quick "
  "ranges (Today, This Week, This Month, Quarter, Year, Last 30 Days).")
h2("12.1 KPI Cards")
b("Total Members, Average Attendance, First Timers, Total Items, Pending Maintenance, and Active "
  "Sessions (the number of distinct sessions still active within the selected period).")
h2("12.2 Tabbed Sections")
b("Overview – attendance trend, member demographics, inventory status, upcoming maintenance.")
b("Members – member growth, categories, Recent First Timers and Most Active Members tables.")
b("Attendance – top sessions, check-in methods breakdown, recent sessions.")
b("Inventory – value over time, value by category, high-value items, items needing attention.")
b("Maintenance – cost over time, status breakdown, recent and upcoming maintenance.")
p("All data tables on the dashboard support search, sorting, and pagination. Sections load on "
  "demand when their tab is opened, keeping the page responsive.")

h1("13. Notifications and Email")
p("The system sends emails for key events, such as welcome/QR-code messages for new members and "
  "one-time codes for password resets. Email delivery is handled through the configured mail "
  "provider.")

h1("14. Security Summary")
b("Role-Based Access Control restricts every page and action to authorised roles/permissions.")
b("Idle auto-logout protects unattended sessions.")
b("Secure password reset uses emailed one-time codes that expire.")
b("Cross-site request forgery (CSRF) protection guards form submissions.")
b("Completed sessions are locked against further check-ins.")
b("Biometric credentials use device-based WebAuthn; fingerprints never leave the device.")

h1("15. Quick Reference – Who Can Do What")
b("Member (User role): sign in, view home/dashboard, self check-in, view own profile and QR code.")
b("Attendance Officer (Admin or a custom role with session permissions): add members to sessions "
  "via barcode/biometric/QR, view session attendance.")
b("Administrator (Admin role): everything – manage users, roles, sessions, inventory, "
  "analytics, biometrics, and account resets.")

spacer()
p("End of document. For assistance, contact your system administrator.")

# ---------------------------------------------------------------- OOXML
W = 'http://schemas.openxmlformats.org/wordprocessingml/2006/main'

def para(style, text):
    t = escape(text)
    ppr = f'<w:pPr><w:pStyle w:val="{style}"/></w:pPr>' if style else ''
    return (f'<w:p>{ppr}<w:r><w:t xml:space="preserve">{t}</w:t></w:r></w:p>')

STYLE_MAP = {
    'title': 'Title', 'subtitle': 'Subtitle', 'h1': 'Heading1',
    'h2': 'Heading2', 'h3': 'Heading3', 'p': 'Normal', 'bullet': 'ListBullet',
}

body_parts = []
for kind, text in blocks:
    if kind == 'spacer':
        body_parts.append('<w:p/>')
    else:
        body_parts.append(para(STYLE_MAP.get(kind, 'Normal'), text))

sectpr = ('<w:sectPr><w:pgSz w:w="12240" w:h="15840"/>'
          '<w:pgMar w:top="1440" w:right="1440" w:bottom="1440" w:left="1440" '
          'w:header="720" w:footer="720" w:gutter="0"/></w:sectPr>')

document_xml = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    f'<w:document xmlns:w="{W}"><w:body>'
    + ''.join(body_parts) + sectpr +
    '</w:body></w:document>'
)

def heading_style(sid, name, size_half_pt, color, before=240, after=120, outline=None):
    ol = f'<w:outlineLvl w:val="{outline}"/>' if outline is not None else ''
    return (
        f'<w:style w:type="paragraph" w:styleId="{sid}"><w:name w:val="{name}"/>'
        '<w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:qFormat/>'
        f'<w:pPr><w:keepNext/><w:spacing w:before="{before}" w:after="{after}"/>{ol}</w:pPr>'
        f'<w:rPr><w:rFonts w:ascii="Calibri Light" w:hAnsi="Calibri Light"/><w:b/>'
        f'<w:color w:val="{color}"/><w:sz w:val="{size_half_pt}"/></w:rPr></w:style>'
    )

styles_xml = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    f'<w:styles xmlns:w="{W}">'
    '<w:docDefaults><w:rPrDefault><w:rPr><w:rFonts w:ascii="Calibri" w:hAnsi="Calibri"/>'
    '<w:sz w:val="22"/></w:rPr></w:rPrDefault></w:docDefaults>'
    '<w:style w:type="paragraph" w:default="1" w:styleId="Normal"><w:name w:val="Normal"/>'
    '<w:qFormat/><w:pPr><w:spacing w:after="160" w:line="276" w:lineRule="auto"/></w:pPr></w:style>'
    + heading_style('Title', 'Title', 56, '1F3864', 0, 80)
    + '<w:style w:type="paragraph" w:styleId="Subtitle"><w:name w:val="Subtitle"/>'
      '<w:basedOn w:val="Normal"/><w:qFormat/><w:pPr><w:spacing w:after="240"/></w:pPr>'
      '<w:rPr><w:rFonts w:ascii="Calibri Light" w:hAnsi="Calibri Light"/><w:color w:val="595959"/>'
      '<w:sz w:val="30"/></w:rPr></w:style>'
    + heading_style('Heading1', 'heading 1', 32, '2E74B5', 280, 120, 0)
    + heading_style('Heading2', 'heading 2', 26, '2E74B5', 240, 100, 1)
    + heading_style('Heading3', 'heading 3', 24, '1F4E79', 200, 80, 2)
    + '<w:style w:type="paragraph" w:styleId="ListBullet"><w:name w:val="List Bullet"/>'
      '<w:basedOn w:val="Normal"/><w:qFormat/><w:pPr>'
      '<w:numPr><w:numId w:val="1"/></w:numPr><w:spacing w:after="80"/>'
      '<w:ind w:left="720" w:hanging="360"/></w:pPr></w:style>'
    '</w:styles>'
)

numbering_xml = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    f'<w:numbering xmlns:w="{W}">'
    '<w:abstractNum w:abstractNumId="0"><w:lvl w:ilvl="0"><w:start w:val="1"/>'
    '<w:numFmt w:val="bullet"/><w:lvlText w:val="•"/><w:lvlJc w:val="left"/>'
    '<w:pPr><w:ind w:left="720" w:hanging="360"/></w:pPr>'
    '<w:rPr><w:rFonts w:ascii="Symbol" w:hAnsi="Symbol" w:hint="default"/></w:rPr></w:lvl>'
    '</w:abstractNum>'
    '<w:num w:numId="1"><w:abstractNumId w:val="0"/></w:num>'
    '</w:numbering>'
)

content_types = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
    '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
    '<Default Extension="xml" ContentType="application/xml"/>'
    '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
    '<Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/>'
    '<Override PartName="/word/numbering.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.numbering+xml"/>'
    '</Types>'
)

root_rels = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
    '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>'
    '</Relationships>'
)

doc_rels = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
    '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>'
    '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/numbering" Target="numbering.xml"/>'
    '</Relationships>'
)

with zipfile.ZipFile(OUT, 'w', zipfile.ZIP_DEFLATED) as z:
    z.writestr('[Content_Types].xml', content_types)
    z.writestr('_rels/.rels', root_rels)
    z.writestr('word/document.xml', document_xml)
    z.writestr('word/_rels/document.xml.rels', doc_rels)
    z.writestr('word/styles.xml', styles_xml)
    z.writestr('word/numbering.xml', numbering_xml)

print('Wrote', OUT)
