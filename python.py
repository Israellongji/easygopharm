import smtplib
from email.mime.text import MIMEText

msg = MIMEText("Test email from EasyGoPharm.")
msg["Subject"] = "Test"
msg["From"] = "easygo@easygopharm.com"
msg["To"] = "easygo@easygopharm.com"

server = smtplib.SMTP("smtp.hostinger.com", 587)
server.starttls()
server.login("easygo@easygopharm.com", "Easygo@1")
server.send_message(msg)
server.quit()

print("✅ Sent successfully")
