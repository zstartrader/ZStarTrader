Z STAR TRADER — SERVER SETUP (Roman Urdu)

1) Apne Windows PC par Node.js LTS install karein: https://nodejs.org/
2) Command Prompt khol kar ye commands chalayein:
   cd /d C:\ZStarTrader
   copy .env.example .env
3) .env file Notepad mein kholein aur ye 3 values apne secret passwords se replace karein:
   ADMIN_PASSWORD = admin panel ka password
   SESSION_SECRET = session ke liye alag lamba secret
   DATA_ENCRYPTION_KEY = passkey encryption ke liye alag lamba secret
   Teeno values alag rakhein. .env kisi ke saath share na karein.
4) Dependencies install karein:
   npm install
5) Server start karein:
   npm start
6) Browser mein ye addresses kholein:
   Dashboard: http://localhost:3000/
   Admin:     http://localhost:3000/admin.html

ADMIN PANEL MEIN:
- Naya user add karein: 18-character passkey, UID, tier aur status.
- Search bar mein exact passkey ya UID ka hissa likh kar user dhoondein.
- Edit se passkey, UID, tier aur status update karein.
- Delete se user ka record permanently delete karein.
- Sirf ACTIVE user ki registered passkey dashboard unlock kar sakti hai.

ZAROORI SECURITY NOTES:
- User records SQLite database/database file mein save honge: database/zstartrader.sqlite
- Passkeys database mein encrypted form mein save hoti hain.
- Public internet par deploy karne se pehle HTTPS configure karein aur NODE_ENV=production set karein.
- .env file, admin password aur database backup ko mehfooz rakhein.
- Ye setup local testing ke liye hai; live deployment se pehle hosting/server security configure karna zaroori hai.
