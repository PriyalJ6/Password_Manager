
      // --- Firebase SDK Imports ---
      import { initializeApp } from "https://www.gstatic.com/firebasejs/11.6.1/firebase-app.js";
      import {
        getAuth,
        signInAnonymously,
        onAuthStateChanged,
        signInWithCustomToken,
      } from "https://www.gstatic.com/firebasejs/11.6.1/firebase-auth.js";
      import {
        getFirestore,
        collection,
        onSnapshot,
        addDoc,
        updateDoc,
        deleteDoc,
        doc,
        getDoc,
        setDoc,
        query,
        orderBy,
        serverTimestamp,
        setLogLevel,
      } from "https://www.gstatic.com/firebasejs/11.6.1/firebase-firestore.js";

      // --- Firebase Config and Initialization ---
      // These will be provided by the environment, with fallbacks for local development
      const firebaseConfig =
        typeof __firebase_config !== "undefined"
          ? JSON.parse(__firebase_config)
          : { apiKey: "AIza...", authDomain: "...", projectId: "..." }; // Replace with your actual config for local testing
      const appId =
        typeof __app_id !== "undefined" ? __app_id : "default-app-id";

      const app = initializeApp(firebaseConfig);
      const db = getFirestore(app);
      const auth = getAuth(app);
      setLogLevel("debug"); // For detailed logs, can be set to 'silent' in production

      // --- Global State ---
      let passwords = []; // This will be our local, decrypted cache
      let masterKey = null; // Derived from a user's master password in a real app
      let userId = null;
      let unsubscribePasswords = null; // To detach the Firestore listener
      let unsubscribeLeaderboard = null;
      let unsubscribeForum = null;
      let unsubscribeReplies = null;
      let allForumPosts = []; // To hold all posts for searching
      let confirmCallback = null;

      // --- DOM Elements ---
      const navLinks = document.querySelectorAll(".nav-link");
      const contentSections = document.querySelectorAll(".content-section");
      const addPasswordBtn = document.getElementById("add-password-btn");
      const passwordModal = document.getElementById("password-modal");
      const cancelBtn = document.getElementById("cancel-btn");
      const passwordForm = document.getElementById("password-form");
      const passwordListEl = document.getElementById("password-list");
      const modalGenerateBtn = document.getElementById("modal-generate-btn");
      const modalPasswordInput = document.getElementById("password");

      // Generator elements
      const generatedPasswordInput =
        document.getElementById("generated-password");
      const lengthSlider = document.getElementById("length");
      const lengthValue = document.getElementById("length-value");
      const generateBtn = document.getElementById("generate-btn");

      // Security Check elements
      const checkPasswordBtn = document.getElementById("check-password-btn");
      const passwordToCheckInput = document.getElementById("password-to-check");
      const securityCheckResultsEl = document.getElementById(
        "security-check-results"
      );

      // Phishing check elements
      const checkUrlBtn = document.getElementById("check-url-btn");
      const urlToCheckInput = document.getElementById("url-to-check");
      const phishingCheckResultsEl = document.getElementById(
        "phishing-check-results"
      );

      // Chatbot elements
      const chatbotToggle = document.getElementById("chatbot-toggle");
      const chatbotWindow = document.getElementById("chatbot-window");
      const chatForm = document.getElementById("chat-form");
      const chatInput = document.getElementById("chat-input");
      const chatMessages = document.getElementById("chat-messages");

      // Simulation elements
      const simulationSection = document.getElementById("simulation");
      const simulationContentEl = document.getElementById("simulation-content");

      // Forum elements
      const forumListView = document.getElementById("forum-list-view");
      const forumPostView = document.getElementById("forum-post-view");
      const forumPostsContainer = document.getElementById(
        "forum-posts-container"
      );
      const newPostBtn = document.getElementById("new-post-btn");
      const newPostModal = document.getElementById("new-post-modal");
      const newPostForm = document.getElementById("new-post-form");
      const cancelPostBtn = document.getElementById("cancel-post-btn");
      const forumSearchInput = document.getElementById("forum-search-input");

      // Confirmation Modal elements
      const confirmModal = document.getElementById("confirm-modal");
      const confirmOkBtn = document.getElementById("confirm-ok-btn");
      const confirmCancelBtn = document.getElementById("confirm-cancel-btn");

      // Cipher Learn Modal elements
      const cipherLearnModal = document.getElementById("cipher-learn-modal");
      const cipherLearnCloseBtn = document.getElementById(
        "cipher-learn-close-btn"
      );

      // --- Mock Data & Constants ---
      const COMMON_PASSWORDS = new Set([
        "123456",
        "password",
        "123456789",
        "qwerty",
        "111111",
      ]);
      const KNOWN_BREACHED_PASSWORDS = new Set([
        "password123",
        "sunshine",
        "dragon",
        "football",
        "princess",
      ]);
      const KNOWN_PHISHING_SITES = new Set([
        "paypa1.com",
        "go0gle.com",
        "bankofamerlca.com",
      ]);
      const SECURITY_TIPS = [
        "Use a unique password for every account. If one is stolen, the others are safe.",
        "Enable Two-Factor Authentication (2FA) wherever possible. It's like a second lock on your digital door.",
        "Beware of phishing emails. Never click on suspicious links or download attachments from unknown senders.",
        "Regularly update your software and apps to patch security vulnerabilities.",
        "A long password is a strong password. Think of a passphrase like 'CorrectHorseBatteryStaple'.",
      ];

      const PHISHING_SCENARIOS = [
        {
          id: 1,
          difficulty: "easy",
          type: "phishing",
          sender: "Netflix Support <support-team@netflix-logins.com>",
          subject: "Action Required: Your Acount is On Hold!",
          greeting: "Dear Customer,",
          body: "We were unable to validate your billing information for the next billing cycle of your subscription therefore we will suspend your acount. To resolve this, please click the button below to update your payment method.",
          linkText: "Update Payment Details",
          linkHref: "http://netflx-billing-update.xyz",
          redFlags: [
            {
              clue: "sender",
              explanation:
                'The sender email ("netflix-logins.com") is not the official Netflix domain ("netflix.com").',
            },
            {
              clue: "subject",
              explanation:
                'Spelling mistakes like "Acount" and urgent language are common phishing tactics.',
            },
            {
              clue: "greeting",
              explanation:
                'Legitimate companies usually address you by name, not with a generic "Dear Customer".',
            },
            {
              clue: "link",
              explanation:
                "Hovering over the link reveals a suspicious URL that is not the official Netflix website.",
            },
          ],
        },
        {
          id: 2,
          difficulty: "medium",
          type: "phishing",
          sender: "Microsoft Account Team <security-alert@microsft.com>",
          subject: "Unusual sign-in activity",
          greeting: "Hi [Your Name],",
          body: "We detected something unusual about a recent sign-in to the Microsoft account associated with your email. To help keep you safe, we've blocked access to your inbox, contacts list, and calendar for that sign-in. Please review the sign-in and we'll help you take action.",
          linkText: "Review recent activity",
          linkHref: "https://microsft.com.login-activity-345.info",
          redFlags: [
            {
              clue: "sender",
              explanation:
                'The sender domain looks very close, but "microsft.com" is a misspelling of the real "microsoft.com".',
            },
            {
              clue: "link",
              explanation:
                'The link is designed to look legitimate with subdomains, but the actual domain is "login-activity-345.info", not "microsoft.com".',
            },
            {
              clue: "body",
              explanation:
                "While the content is convincing, the threat of blocking access is designed to make you panic and click without thinking.",
            },
          ],
        },
        {
          id: 3,
          difficulty: "hard",
          type: "phishing",
          sender: "Your University IT Help Desk <it-support@your-uni.ac.uk.co>",
          subject: "ACTION REQUIRED: Student Email Migration",
          greeting: "Dear Student,",
          body: "As part of our scheduled system maintenance, we are migrating all student email accounts to a new server. To ensure continued access to your email and university portal, you must verify your credentials by clicking the link below before Friday at 5 PM. Failure to do so may result in temporary loss of access.",
          linkText: "Verify Your Account Now",
          linkHref: "https://your-uni-portal.com/verify?id=s1234567",
          redFlags: [
            {
              clue: "sender",
              explanation:
                'The sender domain ends in ".ac.uk.co", a trick to make it look like a UK academic site, but the real domain is ".co". Your university\'s real domain would likely be just ".ac.uk".',
            },
            {
              clue: "urgency",
              explanation:
                'Creating a strict deadline ("Friday at 5 PM") is a classic high-pressure tactic used in spear phishing.',
            },
            {
              clue: "link",
              explanation:
                'The link leads to "your-uni-portal.com", which could be a convincing fake. A real university link would be on their primary domain, like "portal.your-uni.ac.uk".',
            },
          ],
        },
        {
          id: 4,
          difficulty: "easy",
          type: "legitimate",
          sender: "Spotify <no-reply@spotify.com>",
          subject: "Your weekly playlist is ready",
          greeting: "Hey [Your Name]!",
          body: "Your Discover Weekly has been updated with 30 new songs we think you'll love. Listen now and enjoy your personalized soundtrack for the week.",
          linkText: "Listen Now",
          linkHref: "https://open.spotify.com/playlist/37i9dQZEVXc12345",
          redFlags: [],
        },
      ];

      const DATA_BREACH_SCENARIOS = [
        {
          id: 1,
          difficulty: "easy",
          title: "University Portal Breach",
          startNode: "start",
          nodes: {
            start: {
              text: "You receive an official-looking email from the university IT department stating that the student SSO portal has experienced a security breach. What is your IMMEDIATE first step?",
              choices: [
                {
                  text: "Go to the official university portal website and change your password.",
                  next: "changedPassword",
                },
                {
                  text: "Click the 'Reset Password' link in the email to secure your account quickly.",
                  explanation:
                    "This is likely a phishing attack. You should never click links in unexpected security emails. Always go directly to the official website by typing the address yourself.",
                },
                {
                  text: "Call a friend to see if they got the email too.",
                  explanation:
                    "While sharing information is good, your personal security is the top priority. Act immediately to protect your account before doing anything else.",
                },
              ],
            },
            changedPassword: {
              text: "Excellent! You avoided a potential phishing trap and secured the primary account. Now, what's your next priority?",
              choices: [
                {
                  text: "Think about any other websites where you reused this same password.",
                  next: "checkReuse",
                },
                {
                  text: "Assume you're safe now and go back to studying.",
                  explanation:
                    "This is a common mistake. Attackers will immediately try your compromised password on other popular sites. You must check for password reuse.",
                },
                {
                  text: "Post on social media to warn everyone.",
                  explanation:
                    "Warning others is helpful, but only after you have fully secured all of your own affected accounts. Your priority is to contain your own breach first.",
                },
              ],
            },
            checkReuse: {
              text: "Smart move. Password reuse is a major risk. You remember using the same password for your personal email and the 'Campus Eats' food delivery app. What do you do?",
              choices: [
                {
                  text: "Change the passwords on BOTH your personal email and the food app, making them unique.",
                  next: "remediated",
                },
                {
                  text: "Just change the food app password; your email is probably fine.",
                  explanation:
                    "Your email is one of your most critical accounts! It's the key to resetting other passwords. It should be your highest priority to secure.",
                },
                {
                  text: "Just change the email password; the food app isn't important.",
                  explanation:
                    "While less critical than your email, an attacker could still use the food app account to find personal information or make fraudulent orders. You must secure every account that shared the password.",
                },
              ],
            },
            remediated: {
              text: "Perfect! By changing passwords on all affected accounts with unique, strong credentials, you have successfully contained the breach. As a final step, what should you enable on these critical accounts?",
              choices: [
                {
                  text: "Enable Multi-Factor Authentication (MFA/2FA).",
                  next: "win",
                },
                {
                  text: "Write the new passwords down on a sticky note.",
                  explanation:
                    "Writing passwords down is a major security risk. A password manager is the right way to store them. The best final step here is enabling MFA for an extra layer of protection.",
                },
              ],
            },
            win: {
              end: true,
              success: true,
              title: "Challenge Complete!",
              text: "Congratulations! You handled the data breach perfectly. You secured your accounts, eliminated the risk from password reuse, and hardened your security with MFA. You've successfully protected your digital life.",
            },
          },
        },
      ];

      const DIGITAL_FOOTPRINT_SCENARIO = {
        target: "Alex Taylor",
        mission:
          "Find Alex's full birthday, pet's name, and dorm building from their social media posts.",
        clues: {
          birthday: {
            label: "Full Birthday (MM/DD/YYYY)",
            value: null,
            answer: "08/15/2005",
            found: false,
            attackVector:
              "This is a core piece of Personally Identifiable Information (PII). It can be used to open fraudulent accounts, verify identity with banks, and bypass security checks.",
          },
          petName: {
            label: "Pet's Name",
            value: null,
            answer: "Rocky",
            found: false,
            attackVector:
              "This is one of the most common security question answers. An attacker would immediately try 'Rocky' to reset your email, banking, and social media passwords.",
          },
          dorm: {
            label: "Dorm Building",
            value: null,
            answer: "Maple Hall",
            found: false,
            attackVector:
              "Knowing your physical location makes you vulnerable to social engineering (e.g., faking a delivery) or even physical theft by knowing when you post about being away from your room.",
          },
        },
        posts: [
          {
            id: 1,
            author: "Casey Garcia (Alex's Friend)",
            avatar: "https://placehold.co/50x50/2296CE/FFFFFF?text=CG",
            text: "Happy 2-0 to my bestie @AlexTaylor! 🎉 So glad we get to celebrate together! Can't wait for the party tonight!",
            clueType: "birthday",
            clueDetail:
              "A friend's post confirms Alex is turning 20 today (August 15th). From this, an attacker can deduce the birth year is 2005.",
            date: "August 15, 2025",
          },
          {
            id: 2,
            author: "Alex Taylor",
            avatar: "https://placehold.co/50x50/7E22CE/FFFFFF?text=AT",
            text: "Got my study buddy with me for this late-night session. He's not much help with calculus though.",
            image:
              "https://placehold.co/400x250/cccccc/333333?text=Dog+with+a+tag+that+reads+'Rocky'",
            clueType: "petName",
            clueDetail:
              "The pet's name, 'Rocky', is visible on the dog tag in the photo. Attackers look for small details like this.",
            date: "September 5, 2025",
          },
          {
            id: 3,
            author: "Alex Taylor",
            avatar: "https://placehold.co/50x50/7E22CE/FFFFFF?text=AT",
            text: "Finally settled in for the new semester! The view is pretty sweet.",
            image:
              "https://placehold.co/400x250/cccccc/333333?text=View+from+a+dorm+window+with+'Maple+Hall'+sign+visible",
            clueType: "dorm",
            clueDetail:
              "A sign for 'Maple Hall' is visible in the background of this photo, revealing the dorm's name.",
            date: "August 28, 2025",
          },
          {
            id: 4,
            author: "Alex Taylor",
            avatar: "https://placehold.co/50x50/7E22CE/FFFFFF?text=AT",
            text: "Great weekend trip to the beach! So ready to come back and crash.",
            clueType: null,
            date: "September 12, 2025",
          },
        ],
      };

      const CIPHER_CHALLENGE = {
        title: "Operation: Campus Pranksters",
        currentMissionLevels: [],
        currentLevelIndex: 0,
        questionBank: {
          caesar: [
            {
              encrypted: "URYYB, JBEYQ! ZVGGVAT NG GUR YVOENEL.",
              decrypted: "HELLO, WORLD! MEETING AT THE LIBRARY.",
              clue: "The ancient Romans liked to SHIFT things around. The key is in the middle of everything (13).",
            },
            {
              encrypted: "GUR NFFVTAZRAG VF QHR BA ZBAQNL.",
              decrypted: "THE ASSIGNMENT IS DUE ON MONDAY.",
              clue: "It seems like a simple letter shift. Have you tried the most common one?",
            },
            {
              encrypted: "JUNG GVZR VF GUR RKNZ?",
              decrypted: "WHAT TIME IS THE EXAM?",
              clue: "Julius Caesar's favorite number was unlucky for some. Try a shift of 13.",
            },
            {
              encrypted: "FRPHER CNFFJBEQ VF VZCBEGNAG.",
              decrypted: "SECURE PASSWORD IS IMPORTANT.",
              clue: "This message is rotated halfway through the alphabet.",
            },
            {
              encrypted: "CYRNFR YBPX GUR QBBE.",
              decrypted: "PLEASE LOCK THE DOOR.",
              clue: "A simple rotation is all that's hiding this message.",
            },
          ],
          atbash: [
            {
              encrypted: "GSV GZITVG RH GSV NZHXLGH HGZGFV.",
              decrypted: "THE TARGET IS THE MASCOTS STATUE.",
              clue: "Sometimes, the simplest trick is to REVERSE your thinking. What's the opposite of A?",
            },
            {
              encrypted: "YV HZUV LMORVM.",
              decrypted: "BE SAFE ONLINE.",
              clue: "Think backwards. A becomes Z, B becomes Y...",
            },
            {
              encrypted: "Z XBKsvi rh mlg z kvihlm.",
              decrypted: "A CIPHER IS NOT A PERSON.",
              clue: "Every letter has been swapped with its counterpart from the other end of the alphabet.",
            },
            {
              encrypted: "GL WVXIBKG RH GL HLOEV.",
              decrypted: "TO DECRYPT IS TO SOLVE.",
              clue: "This cipher is a mirror image of the alphabet.",
            },
            {
              encrypted: "GSRH RH Z GVHG.",
              decrypted: "THIS IS A TEST.",
              clue: "The first letter becomes the last, the last becomes the first.",
            },
          ],
          keyword: [
            // NOTE: All these use the keyword 'LIBRARY' which is revealed in the first Caesar cipher message.
            {
              encrypted: "USV ALQD MW QS LMQLMISU.",
              decrypted: "THE PLAN IS AT MIDNIGHT.",
              clue: "The first decrypted message told you our meeting spot. That word is the KEY.",
            },
            {
              encrypted: "AEMLG USV XSYWVLS YQG.",
              decrypted: "BRING THE CONFETTI CAN.",
              clue: "The key is the location mentioned in the first intercepted message.",
            },
            {
              encrypted: "Q'Y DSEEMLG USV CSQFV.",
              decrypted: "I'M BRINGING THE CAKE.",
              clue: "Use the keyword you discovered in the first stage of the mission.",
            },
            {
              encrypted: "L'U EV Q KEQGUS.",
              decrypted: "IT'S GOING TO BE A BLAST.",
              clue: "The location is the key to this message.",
            },
            {
              encrypted: "L'UU WVV Q KWEAEMWV.",
              decrypted: "IT'LL BE A SURPRISE.",
              clue: "Remember where the hackers are meeting? That's your keyword.",
            },
          ],
        },
      };

      const CIPHER_EXPLANATIONS = {
        Caesar: {
          title: "The Caesar Cipher",
          explanation:
            "The Caesar cipher is one of the oldest forms of encryption. It's a substitution cipher where each letter in the plaintext is 'shifted' a certain number of places down the alphabet.",
          example: `
                    <p><b>Plaintext:</b> <span class="font-mono">ATTACK</span></p>
                    <p><b>Key:</b> Shift by 3</p>
                    <p><b>Process:</b> <span class="font-mono">A &rarr; D, T &rarr; W, T &rarr; W, A &rarr; D, C &rarr; F, K &rarr; N</span></p>
                    <p><b>Ciphertext:</b> <span class="font-mono">DWWDFN</span></p>`,
          weakness:
            "<b>Weakness:</b> It's very easy to break. Since there are only 25 possible shifts, an attacker can try all of them in a method called a 'brute-force attack' and find the message in seconds.",
        },
        Atbash: {
          title: "The Atbash Cipher",
          explanation:
            "The Atbash cipher is another simple substitution cipher where the alphabet is reversed. The first letter (A) becomes the last letter (Z), the second letter (B) becomes the second to last (Y), and so on.",
          example: `
                     <p><b>Plaintext:</b> <span class="font-mono">HACK</span></p>
                    <p><b>Key:</b> Reversed Alphabet</p>
                    <p><b>Process:</b> <span class="font-mono">A&harr;Z, B&harr;Y, C&harr;X...</span></p>
                    <p><b>Ciphertext:</b> <span class="font-mono">SZXP</span></p>`,
          weakness:
            "<b>Weakness:</b> Like the Caesar cipher, this is extremely weak. There is only one way to apply it, so an attacker only has to check for a reversed alphabet to break it instantly.",
        },
        Keyword: {
          title: "The Keyword Cipher",
          explanation:
            "A keyword cipher uses a secret word (the 'keyword') to create a mixed-up alphabet for substitution. You write the keyword first (removing duplicate letters), then write the rest of the alphabet in order.",
          example: `
                     <p><b>Plaintext:</b> <span class="font-mono">SECRET MESSAGE</span></p>
                    <p><b>Keyword:</b> <span class="font-mono">SECURITY</span></p>
                    <p><b>Cipher Alphabet:</b> <span class="font-mono"><b>SECURIT</b>YABDFGHJKLMN OPQVWXZ</span></p>
                    <p><b>Process:</b> <span class="font-mono">S becomes S, E becomes E, C becomes C... M becomes J...</span></p>`,
          weakness:
            "<b>Weakness:</b> While stronger than Caesar, it's still vulnerable to frequency analysis, where attackers analyze how often letters appear to guess the keyword.",
        },
      };

      let currentChallenge = null;
      let userScore = 0;
      let currentBreachScenario = null;
      let currentBreachNodeKey = null;
      let answeredChoices = new Set();

      // --- Core Functions ---

      // Simulate getting a master key on login
      async function getMasterKey() {
        if (masterKey) return masterKey;
        // In a real app, this would be derived from a password using PBKDF2
        const pseudoMasterPassword = "a-very-secure-student-password";
        const enc = new TextEncoder();
        const keyMaterial = await crypto.subtle.importKey(
          "raw",
          enc.encode(pseudoMasterPassword),
          { name: "PBKDF2" },
          false,
          ["deriveKey"]
        );
        masterKey = await crypto.subtle.deriveKey(
          {
            name: "PBKDF2",
            salt: enc.encode("some-static-salt"), // Use a unique, per-user salt in a real app
            iterations: 100000,
            hash: "SHA-256",
          },
          keyMaterial,
          { name: "AES-GCM", length: 256 },
          true,
          ["encrypt", "decrypt"]
        );
        return masterKey;
      }

      async function encrypt(data) {
        const key = await getMasterKey();
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const enc = new TextEncoder();
        const encodedData = enc.encode(data);
        const encryptedData = await crypto.subtle.encrypt(
          { name: "AES-GCM", iv: iv },
          key,
          encodedData
        );
        // Return an object that can be stored in Firestore
        return {
          iv: btoa(String.fromCharCode.apply(null, iv)), // Base64 encode IV
          data: btoa(
            String.fromCharCode.apply(null, new Uint8Array(encryptedData))
          ), // Base64 encode data
        };
      }

      async function decrypt(encryptedObj) {
        const key = await getMasterKey();
        // Decode from Base64
        const iv = new Uint8Array(
          atob(encryptedObj.iv)
            .split("")
            .map((c) => c.charCodeAt(0))
        );
        const data = new Uint8Array(
          atob(encryptedObj.data)
            .split("")
            .map((c) => c.charCodeAt(0))
        );

        const decryptedData = await crypto.subtle.decrypt(
          { name: "AES-GCM", iv: iv },
          key,
          data
        );
        const dec = new TextDecoder();
        return dec.decode(decryptedData);
      }

      function renderPasswords() {
        if (passwords.length === 0) {
          passwordListEl.innerHTML = `<p class="text-center text-gray-500 p-8">No passwords saved yet. Click 'Add New' to get started!</p>`;
          return;
        }

        passwordListEl.innerHTML = `
                <div class="grid grid-cols-5 gap-4 font-bold text-gray-500 p-4 border-b">
                    <div>Website</div>
                    <div>Username</div>
                    <div>Password</div>
                    <div>Last Modified</div>
                    <div>Actions</div>
                </div>
            `;
        passwords.forEach((p) => {
          const passwordItem = document.createElement("div");
          passwordItem.className =
            "grid grid-cols-5 gap-4 items-center p-4 border-b hover:bg-gray-50";
          passwordItem.innerHTML = `
                    <div class="font-medium">${p.website}</div>
                    <div>${p.username}</div>
                    <div class="flex items-center">
                        <span class="password-dots">••••••••</span>
                        <span class="password-text hidden text-green-700"></span>
                        <button class="ml-4 text-gray-500 reveal-password" data-id="${
                          p.id
                        }"><i class="fas fa-eye"></i></button>
                    </div>
                    <div>${
                      p.lastModified
                        ? p.lastModified.toDate().toLocaleDateString()
                        : "N/A"
                    }</div>
                    <div>
                        <button class="edit-btn text-blue-600 mr-4" data-id="${
                          p.id
                        }"><i class="fas fa-edit"></i></button>
                        <button class="delete-btn text-red-600" data-id="${
                          p.id
                        }"><i class="fas fa-trash"></i></button>
                    </div>
                `;
          passwordListEl.appendChild(passwordItem);
        });
      }

      async function updateDashboard() {
        document.getElementById("total-passwords").textContent =
          passwords.length;

        let weakCount = 0;
        const passwordSet = new Set();
        let reusedCount = 0;

        // We need to decrypt passwords to analyze them.
        // This happens client-side, so it remains secure.
        for (const p of passwords) {
          const decryptedPassword = await decrypt(p.encryptedPassword);
          if (
            decryptedPassword.length < 10 ||
            COMMON_PASSWORDS.has(decryptedPassword)
          ) {
            weakCount++;
          }
          if (passwordSet.has(decryptedPassword)) {
            reusedCount++;
          } else {
            passwordSet.add(decryptedPassword);
          }
        }

        document.getElementById("weak-passwords").textContent = weakCount;
        document.getElementById("reused-passwords").textContent = reusedCount;

        const score =
          passwords.length > 0
            ? Math.round(
                ((passwords.length - weakCount - reusedCount) /
                  passwords.length) *
                  100
              )
            : "N/A";
        document.getElementById("overall-score").textContent =
          score === "N/A" ? "N/A" : `${score}%`;
      }

      async function showModal(password = null) {
        passwordForm.reset();
        const modalTitle = document.getElementById("modal-title");
        if (password) {
          modalTitle.textContent = "Edit Password";
          const decryptedPassword = await decrypt(password.encryptedPassword);
          document.getElementById("password-id").value = password.id;
          document.getElementById("website").value = password.website;
          document.getElementById("username").value = password.username;
          modalPasswordInput.value = decryptedPassword;
          // Trigger strength check on existing password
          modalPasswordInput.dispatchEvent(new Event("input"));
        } else {
          modalTitle.textContent = "Add New Password";
          document.getElementById("password-id").value = "";
          document
            .getElementById("modal-strength-container")
            .classList.add("hidden");
        }
        passwordModal.classList.remove("hidden");
      }

      function hideModal() {
        passwordModal.classList.add("hidden");
      }

      function getPasswordStrength(password) {
        let score = 0;
        if (password.length > 8) score++;
        if (password.length > 12) score++;
        if (/[A-Z]/.test(password)) score++;
        if (/[a-z]/.test(password)) score++;
        if (/[0-9]/.test(password)) score++;
        if (/[^A-Za-z0-9]/.test(password)) score++;

        if (score < 3) return { label: "Weak", class: "weak" };
        if (score < 5) return { label: "Medium", class: "medium" };
        if (score < 6) return { label: "Strong", class: "strong" };
        return { label: "Very Strong", class: "very-strong" };
      }

      function showConfirmModal(title, text, callback) {
        document.getElementById("confirm-title").textContent = title;
        document.getElementById("confirm-text").textContent = text;
        confirmCallback = callback;
        confirmModal.classList.remove("hidden");
      }

      function hideConfirmModal() {
        confirmModal.classList.add("hidden");
        confirmCallback = null;
      }

      function handleHashChange() {
        const hash = window.location.hash.substring(1); // e.g., 'dashboard'
        const targetId = hash || "dashboard"; // Default to dashboard if no hash

        const targetLink = document.querySelector(
          `.nav-link[data-target="${targetId}"]`
        );
        const targetSection = document.getElementById(targetId);

        if (targetLink && targetSection) {
          navLinks.forEach((l) =>
            l.classList.remove("active", "bg-purple-700")
          );
          targetLink.classList.add("active", "bg-purple-700");

          contentSections.forEach((section) => {
            if (section.id === targetId) {
              section.classList.remove("hidden");
            } else {
              section.classList.add("hidden");
            }
          });
        }
      }

      // --- Event Listeners ---

      // Navigation
      navLinks.forEach((link) => {
        link.addEventListener("click", (e) => {
          e.preventDefault();
          const targetId = link.dataset.target;
          // Update URL hash without reloading the page
          window.location.hash = targetId;
        });
      });

      // Password Modal
      addPasswordBtn.addEventListener("click", () => showModal());
      cancelBtn.addEventListener("click", hideModal);
      passwordModal.addEventListener("click", (e) => {
        if (e.target === passwordModal) {
          hideModal();
        }
      });

      // Confirmation Modal
      confirmOkBtn.addEventListener("click", () => {
        if (confirmCallback) {
          confirmCallback();
        }
        hideConfirmModal();
      });
      confirmCancelBtn.addEventListener("click", hideConfirmModal);
      confirmModal.addEventListener("click", (e) => {
        if (e.target === confirmModal) {
          hideConfirmModal();
        }
      });

      // Password Form Submission
      passwordForm.addEventListener("submit", async (e) => {
        e.preventDefault();
        if (!userId) {
          console.error("User not authenticated!");
          return;
        }

        const id = document.getElementById("password-id").value;
        const website = document.getElementById("website").value;
        const username = document.getElementById("username").value;
        const password = document.getElementById("password").value;

        const encryptedPassword = await encrypt(password);

        const passwordData = {
          website,
          username,
          encryptedPassword,
          lastModified: serverTimestamp(),
        };

        try {
          if (id) {
            // Editing
            const docRef = doc(
              db,
              `artifacts/${appId}/users/${userId}/passwords`,
              id
            );
            await updateDoc(docRef, passwordData);
          } else {
            // Adding
            const collectionRef = collection(
              db,
              `artifacts/${appId}/users/${userId}/passwords`
            );
            await addDoc(collectionRef, passwordData);
          }
          hideModal();
        } catch (error) {
          console.error("Error saving password: ", error);
        }
      });

      // Password List Actions (Reveal, Edit, Delete)
      passwordListEl.addEventListener("click", async (e) => {
        const target = e.target.closest("button");
        if (!target) return;

        const id = target.dataset.id;
        if (target.classList.contains("reveal-password")) {
          const passwordItem = target.closest(".grid");
          const passwordDots = passwordItem.querySelector(".password-dots");
          const passwordText = passwordItem.querySelector(".password-text");
          const icon = target.querySelector("i");

          if (passwordText.classList.contains("hidden")) {
            const passwordEntry = passwords.find((p) => p.id == id);
            if (passwordEntry) {
              const decryptedPass = await decrypt(
                passwordEntry.encryptedPassword
              );
              passwordText.textContent = decryptedPass;

              passwordDots.classList.add("hidden");
              passwordText.classList.remove("hidden");
              icon.classList.replace("fa-eye", "fa-eye-slash");
            }
          } else {
            passwordDots.classList.remove("hidden");
            passwordText.classList.add("hidden");
            icon.classList.replace("fa-eye-slash", "fa-eye");
          }
        } else if (target.classList.contains("edit-btn")) {
          const passwordToEdit = passwords.find((p) => p.id == id);
          showModal(passwordToEdit);
        } else if (target.classList.contains("delete-btn")) {
          showConfirmModal(
            "Delete Password",
            "Are you sure you want to permanently delete this password entry?",
            async () => {
              try {
                const docRef = doc(
                  db,
                  `artifacts/${appId}/users/${userId}/passwords`,
                  id
                );
                await deleteDoc(docRef);
              } catch (error) {
                console.error("Error deleting password: ", error);
              }
            }
          );
        }
      });

      // Toggle password visibility in modal
      document
        .querySelector(".toggle-password")
        .addEventListener("click", function () {
          const passwordInput = document.getElementById("password");
          const icon = this.querySelector("i");
          if (passwordInput.type === "password") {
            passwordInput.type = "text";
            icon.classList.replace("fa-eye", "fa-eye-slash");
          } else {
            passwordInput.type = "password";
            icon.classList.replace("fa-eye-slash", "fa-eye");
          }
        });

      // Live password strength check in modal
      modalPasswordInput.addEventListener("input", () => {
        const password = modalPasswordInput.value;
        const strengthContainer = document.getElementById(
          "modal-strength-container"
        );
        const strengthBar = document.getElementById("modal-strength-bar");
        const strengthText = document.getElementById("modal-strength-text");

        if (!password) {
          strengthContainer.classList.add("hidden");
          return;
        }

        strengthContainer.classList.remove("hidden");
        const strength = getPasswordStrength(password);

        // Remove all existing strength classes
        strengthBar.classList.remove("weak", "medium", "strong", "very-strong");
        // Add the new class
        strengthBar.classList.add(strength.class);

        strengthText.textContent = `Strength: ${strength.label}`;
        strengthText.className = `text-sm mt-1 text-${
          strength.class === "weak"
            ? "red"
            : strength.class === "medium"
            ? "yellow"
            : "green"
        }-600`;
      });

      // Generate password inside modal
      modalGenerateBtn.addEventListener("click", () => {
        const newPassword = createStrongPassword();
        modalPasswordInput.value = newPassword;
        // Trigger the input event to update the strength meter
        modalPasswordInput.dispatchEvent(new Event("input"));
      });

      // --- Generator Logic ---
      function createStrongPassword() {
        const length = 16; // Hardcode a strong length for this helper
        const chars = {
          uppercase: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
          lowercase: "abcdefghijklmnopqrstuvwxyz",
          numbers: "0123456789",
          symbols: "!@#$%^&*()_+-=[]{}|;:,.<>?",
        };

        let charset =
          chars.uppercase + chars.lowercase + chars.numbers + chars.symbols;

        let password = "";
        const randomValues = new Uint32Array(length);
        crypto.getRandomValues(randomValues);

        for (let i = 0; i < length; i++) {
          password += charset[randomValues[i] % charset.length];
        }
        return password;
      }

      function generatePassword() {
        generatedPasswordInput.value = createStrongPassword();
      }

      lengthSlider.addEventListener("input", (e) => {
        lengthValue.textContent = e.target.value;
      });
      generateBtn.addEventListener("click", generatePassword);

      document
        .getElementById("copy-generated-btn")
        .addEventListener("click", () => {
          const passwordToCopy = generatedPasswordInput.value;
          if (!passwordToCopy || passwordToCopy === "Select an option!") return;

          const textArea = document.createElement("textarea");
          textArea.value = passwordToCopy;
          textArea.style.position = "fixed";
          textArea.style.opacity = 0;
          document.body.appendChild(textArea);
          textArea.select();
          try {
            document.execCommand("copy");
            const btn = document.getElementById("copy-generated-btn");
            const icon = btn.querySelector("i");
            icon.classList.replace("fa-copy", "fa-check");
            btn.classList.add("text-green-500");
            setTimeout(() => {
              icon.classList.replace("fa-check", "fa-copy");
              btn.classList.remove("text-green-500");
            }, 2000);
          } catch (err) {
            console.error("Failed to copy password: ", err);
          }
          document.body.removeChild(textArea);
        });

      // --- Security Check Logic ---

      function generatePasswordSuggestions(password) {
        if (!password || password.length < 4) return [];

        const suggestions = new Set();
        const year = new Date().getFullYear();

        // Suggestion 1: Leetspeak + Suffix
        const leetMap = { a: "@", e: "3", i: "!", o: "0", s: "$" };
        let leetPass = password
          .split("")
          .map((char) => leetMap[char.toLowerCase()] || char)
          .join("");
        if (leetPass !== password) {
          suggestions.add(leetPass + (year % 100));
        }

        // Suggestion 2: Capitalize + Suffix
        let capPass = password.charAt(0).toUpperCase() + password.slice(1);
        if (!/\d/.test(capPass)) capPass += "1";
        if (!/[^A-Za-z0-9]/.test(capPass)) capPass += "!";
        if (capPass !== password) {
          suggestions.add(capPass);
        }

        // Suggestion 3: Add complex suffix
        let suffixPass = password + `_${year}!`;
        suggestions.add(suffixPass);

        // Suggestion 4: Simple Passphrase
        if (!password.includes(" ")) {
          suggestions.add(`My_${password}_Key#${year}`);
        }

        return Array.from(suggestions).slice(0, 3); // Return up to 3 unique suggestions
      }

      async function checkPwnedPassword(password) {
        // 1. Hash the password using SHA-1 (as required by the HIBP API)
        const encoder = new TextEncoder();
        const data = encoder.encode(password);
        const hashBuffer = await crypto.subtle.digest("SHA-1", data);

        // 2. Convert hash to hex string
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        const hashHex = hashArray
          .map((b) => b.toString(16).padStart(2, "0"))
          .join("")
          .toUpperCase();

        // 3. Split the hash into prefix (first 5 chars) and suffix
        const prefix = hashHex.substring(0, 5);
        const suffix = hashHex.substring(5);

        // 4. Call the HIBP API with the prefix
        const response = await fetch(
          `https://api.pwnedpasswords.com/range/${prefix}`
        );
        if (!response.ok) {
          throw new Error("Failed to fetch data from HIBP API");
        }
        const text = await response.text();

        // 5. Check if the suffix exists in the response
        const lines = text.split("\n");
        for (const line of lines) {
          const [hashSuffix, count] = line.split(":");
          if (hashSuffix === suffix) {
            return { pwned: true, count: parseInt(count, 10) };
          }
        }

        return { pwned: false, count: 0 };
      }

      checkPasswordBtn.addEventListener("click", async () => {
        const password = passwordToCheckInput.value;
        if (!password) {
          securityCheckResultsEl.innerHTML = `<p class="text-yellow-600">Please enter a password to analyze.</p>`;
          return;
        }

        // Show initial structure with a loading indicator for the breach check
        securityCheckResultsEl.innerHTML = `
                <h4 class="font-bold text-lg mb-2">Analysis Results:</h4>
                <div id="analysis-content" class="space-y-3">
                     <div class="flex items-center justify-between">
                        <span>Strength:</span>
                        <span id="strength-label" class="font-bold">...</span>
                    </div>
                     <div class="w-full bg-gray-200 rounded-full">
                        <div id="strength-bar" class="password-strength-bar rounded-full"></div>
                    </div>
                    <div class="flex items-center justify-between">
                        <span>Found in Breaches:</span>
                        <span id="breach-status" class="font-bold animate-pulse">Checking...</span>
                    </div>
                     <div class="flex items-center justify-between">
                        <span>Common Password:</span>
                        <span id="common-status" class="font-bold">...</span>
                    </div>
                </div>
                <div id="recommendations-container"></div>
            `;

        const strength = getPasswordStrength(password);
        const isCommon = COMMON_PASSWORDS.has(password);

        // Update static parts of the UI first
        document.getElementById("strength-label").textContent = strength.label;
        document.getElementById("strength-label").className = `font-bold text-${
          strength.class === "weak"
            ? "red"
            : strength.class === "medium"
            ? "yellow"
            : "green"
        }-500`;
        document.getElementById(
          "strength-bar"
        ).className = `password-strength-bar rounded-full ${strength.class}`;
        document.getElementById("common-status").textContent = isCommon
          ? "Yes"
          : "No";
        document.getElementById("common-status").className = `font-bold ${
          isCommon ? "text-red-500" : "text-green-500"
        }`;

        let breachResultText = "";
        try {
          const pwnedResult = await checkPwnedPassword(password);
          const breachStatusEl = document.getElementById("breach-status");
          breachStatusEl.classList.remove("animate-pulse");
          if (pwnedResult.pwned) {
            breachStatusEl.innerHTML = `<span class="font-bold text-red-500">Yes (${pwnedResult.count.toLocaleString()} times)</span>`;
            breachResultText =
              "<li>This password has appeared in a data breach. Do not use it!</li>";
          } else {
            breachStatusEl.innerHTML = `<span class="font-bold text-green-500">No</span>`;
          }
        } catch (error) {
          console.error("Breach check failed:", error);
          const breachStatusEl = document.getElementById("breach-status");
          breachStatusEl.classList.remove("animate-pulse");
          breachStatusEl.innerHTML = `<span class="font-bold text-gray-500">Error</span>`;
        }

        const suggestions = generatePasswordSuggestions(password);
        let suggestionsHTML = "";
        if (suggestions.length > 0) {
          suggestionsHTML = `
                    <div class="pt-4 mt-4 border-t">
                        <h5 class="font-semibold text-lg mb-2">Smart Suggestions:</h5>
                        <p class="text-sm text-gray-600 mb-3">Here are some stronger alternatives you can use:</p>
                        <div class="space-y-2">
                `;
          suggestions.forEach((sugg) => {
            suggestionsHTML += `
                        <div class="flex items-center justify-between bg-gray-100 p-2 rounded-lg">
                            <span class="font-mono text-gray-800">${sugg}</span>
                            <button class="copy-suggestion-btn text-gray-500 hover:text-blue-600 ml-4" data-suggestion="${sugg}">
                                <i class="fas fa-copy"></i>
                            </button>
                        </div>
                    `;
          });
          suggestionsHTML += "</div></div>";
        }

        document.getElementById("recommendations-container").innerHTML = `
                 <div class="mt-3">
                    <h5 class="font-semibold mt-2">Recommendations:</h5>
                    <ul class="list-disc list-inside text-sm text-gray-600">
                        ${breachResultText}
                        ${
                          password.length < 12
                            ? "<li>Use at least 12 characters.</li>"
                            : ""
                        }
                        ${
                          !/[A-Z]/.test(password)
                            ? "<li>Include uppercase letters.</li>"
                            : ""
                        }
                        ${
                          !/[a-z]/.test(password)
                            ? "<li>Include lowercase letters.</li>"
                            : ""
                        }
                        ${
                          !/[0-9]/.test(password)
                            ? "<li>Include numbers.</li>"
                            : ""
                        }
                        ${
                          !/[^A-Za-z0-9]/.test(password)
                            ? "<li>Include symbols.</li>"
                            : ""
                        }
                        ${
                          isCommon
                            ? "<li>Avoid common passwords or dictionary words.</li>"
                            : ""
                        }
                    </ul>
                </div>
                ${suggestionsHTML}
            `;
      });

      // --- Event Listener for Copying Suggestions ---
      securityCheckResultsEl.addEventListener("click", function (e) {
        const copyBtn = e.target.closest(".copy-suggestion-btn");
        if (copyBtn) {
          const suggestion = copyBtn.dataset.suggestion;
          const textArea = document.createElement("textarea");
          textArea.value = suggestion;
          textArea.style.position = "fixed";
          textArea.style.opacity = 0;
          document.body.appendChild(textArea);
          textArea.select();
          try {
            document.execCommand("copy");
            const icon = copyBtn.querySelector("i");
            if (icon.classList.contains("fa-copy")) {
              icon.classList.replace("fa-copy", "fa-check");
              copyBtn.classList.add("text-green-500");
              setTimeout(() => {
                icon.classList.replace("fa-check", "fa-copy");
                copyBtn.classList.remove("text-green-500");
              }, 2000);
            }
          } catch (err) {
            console.error("Failed to copy suggestion: ", err);
          }
          document.body.removeChild(textArea);
        }
      });

      // --- Phishing Check Logic ---
      async function checkPhishingUrl(url) {
        // In a real-world application, you would make an API call to a service like PhishTank here.
        // This requires a server-side proxy to handle the API key and avoid CORS issues.
        //
        // --- Example of what a real implementation would look like: ---
        //
        // const apiKey = 'YOUR_PHISHTANK_API_KEY';
        // const proxyUrl = 'https://your-server.com/check-phishing';
        //
        // try {
        //     const response = await fetch(proxyUrl, {
        //         method: 'POST',
        //         headers: { 'Content-Type': 'application/json' },
        //         body: JSON.stringify({ url: url, key: apiKey })
        //     });
        //     const result = await response.json();
        //     return result.isPhishing; // Assuming your proxy returns a simple boolean
        // } catch (error) {
        //     console.error("Phishing check API call failed:", error);
        //     return false; // Fail safe
        // }
        // -----------------------------------------------------------------

        // --- SIMULATED API CALL FOR THIS DEMO ---
        return new Promise((resolve) => {
          setTimeout(() => {
            const domain = url
              .trim()
              .replace(/^(https?:\/\/)?(www\.)?/, "")
              .split("/")[0];
            const isPhishing = KNOWN_PHISHING_SITES.has(domain);
            resolve(isPhishing);
          }, 1000); // Simulate 1 second network delay
        });
      }

      checkUrlBtn.addEventListener("click", async () => {
        const url = urlToCheckInput.value;
        if (!url) {
          phishingCheckResultsEl.innerHTML = `<p class="text-yellow-600">Please enter a URL to check.</p>`;
          return;
        }

        // Show loading state
        phishingCheckResultsEl.innerHTML = `
                <div class="p-4 rounded-lg bg-gray-100 border border-gray-300 text-gray-700 flex items-center justify-center">
                    <i class="fas fa-spinner fa-spin mr-3"></i>
                    <h4 class="font-bold">Analyzing URL...</h4>
                </div>
            `;

        const isPhishing = await checkPhishingUrl(url);

        if (isPhishing) {
          phishingCheckResultsEl.innerHTML = `
                    <div class="p-4 rounded-lg bg-red-100 border border-red-400 text-red-800">
                        <h4 class="font-bold flex items-center"><i class="fas fa-exclamation-triangle mr-2"></i> Warning! This is a known phishing site.</h4>
                        <p class="mt-2">This URL matches an entry in our database of malicious websites. Do not enter any personal information, such as passwords or credit card numbers.</p>
                    </div>
                `;
        } else {
          phishingCheckResultsEl.innerHTML = `
                     <div class="p-4 rounded-lg bg-green-100 border border-green-400 text-green-800">
                        <h4 class="font-bold flex items-center"><i class="fas fa-check-circle mr-2"></i> This site appears to be safe.</h4>
                        <p class="mt-2">This URL was not found in our database of known threats. However, always remain cautious and look for signs of a phishing attempt.</p>
                    </div>
                `;
        }
      });

      // Chatbot toggle
      chatbotToggle.addEventListener("click", () => {
        chatbotWindow.classList.toggle("hidden");
      });

      // --- Chatbot Logic ---
      chatForm.addEventListener("submit", (e) => {
        e.preventDefault();
        const userMessage = chatInput.value.trim();
        if (userMessage) {
          handleUserMessage(userMessage);
          chatInput.value = "";
        }
      });

      function addMessageToChat(message, sender = "bot") {
        const messageEl = document.createElement("div");
        messageEl.textContent = message;

        if (sender === "user") {
          messageEl.className = "chat-bubble user-bubble";
        } else {
          messageEl.className = "chat-bubble bot-bubble";
        }

        // Remove typing indicator if it exists
        const typingIndicator = chatMessages.querySelector(".typing-indicator");
        if (typingIndicator) {
          chatMessages.removeChild(typingIndicator);
        }

        chatMessages.appendChild(messageEl);
        chatMessages.scrollTop = chatMessages.scrollHeight;
      }

      function showTypingIndicator() {
        const typingEl = document.createElement("div");
        typingEl.className = "chat-bubble bot-bubble typing-indicator";
        typingEl.innerHTML = '<span class="animate-pulse">...</span>';
        chatMessages.appendChild(typingEl);
        chatMessages.scrollTop = chatMessages.scrollHeight;
      }

      async function handleUserMessage(message) {
        addMessageToChat(message, "user");
        showTypingIndicator();

        // Check for URLs
        const urlRegex = /(https?:\/\/[^\s]+)/g;
        if (urlRegex.test(message)) {
          const url = message.match(urlRegex)[0];
          const isPhishing = await checkPhishingUrl(url);

          if (isPhishing) {
            addMessageToChat(
              `Warning! The site at that URL is on our list of known phishing sites. It is not safe.`
            );
          } else {
            addMessageToChat(
              `That URL doesn't appear on our list of known threats, but always be cautious.`
            );
          }
          return;
        }

        // Check for passwords (simple heuristic)
        const passwordRegex =
          /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
        if (
          passwordRegex.test(message) ||
          (message.length > 7 && !message.includes(" "))
        ) {
          const strength = getPasswordStrength(message);
          const isCommon = COMMON_PASSWORDS.has(message);
          const isInBreach = KNOWN_BREACHED_PASSWORDS.has(message);
          let feedback = `Password analysis:
- Strength: ${strength.label}.
- Common Password: ${
            isCommon
              ? "Yes, this is a very common password!"
              : "No, that's good."
          }
- Found in Breach: ${
            isInBreach
              ? "Yes! This password has appeared in a data breach and is unsafe."
              : "No, that's good."
          }
`;
          if (
            strength.class === "weak" ||
            strength.class === "medium" ||
            isCommon ||
            isInBreach
          ) {
            feedback += `\nI strongly recommend creating a stronger, more unique password using the Generator.`;
          } else {
            feedback += `\nLooks like a strong password!`;
          }
          addMessageToChat(feedback);
          return;
        }

        // If not a special command, get response from Gemini
        await getGeminiResponse(message);
      }

      async function getGeminiResponse(userQuery) {
        const apiKey = "";
        const apiUrl = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash-preview-05-20:generateContent?key=${apiKey}`;

        const systemPrompt = `You are a friendly and helpful cybersecurity mentor for college students using the StellarPass password manager. Your tone is encouraging, knowledgeable, and never alarming. Your primary goal is to teach good security practices.
            - Provide clear, concise, and actionable advice.
            - If asked about a security concept, explain it in simple terms with a relatable analogy.
            - If asked for an opinion, base it on widely accepted cybersecurity best practices.
            - Do not give legal, financial, or medical advice.
            - Keep responses to a few sentences.
            - If a user mentions a specific breach or problem, guide them on the general steps to take (change password, enable MFA) without asking for their personal information.
            `;

        const payload = {
          contents: [{ parts: [{ text: userQuery }] }],
          systemInstruction: {
            parts: [{ text: systemPrompt }],
          },
        };

        try {
          const response = await fetch(apiUrl, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload),
          });

          if (!response.ok) {
            throw new Error(`API call failed with status: ${response.status}`);
          }

          const result = await response.json();
          const candidate = result.candidates?.[0];

          if (candidate && candidate.content?.parts?.[0]?.text) {
            addMessageToChat(candidate.content.parts[0].text);
          } else {
            addMessageToChat(
              "I'm sorry, I couldn't process that. Could you try asking in a different way?"
            );
          }
        } catch (error) {
          console.error("Gemini API call failed:", error);
          addMessageToChat(
            "Sorry, I'm having trouble connecting right now. Please try again in a moment."
          );
        }
      }

      // --- Simulation Logic ---

      function startPhishingChallenge(difficulty) {
        currentBreachScenario = null; // Clear breach state
        const possibleScenarios = PHISHING_SCENARIOS.filter(
          (s) => s.difficulty === difficulty
        );
        currentChallenge =
          possibleScenarios[
            Math.floor(Math.random() * possibleScenarios.length)
          ];
        renderPhishingEmail(currentChallenge);
      }

      function renderPhishingEmail(scenario) {
        const emailHTML = `
                <div class="bg-white p-8 rounded-xl shadow-md">
                    <button id="back-to-simulations" class="mb-4 text-sm text-blue-600 hover:underline">&larr; Back to Challenges</button>
                    <div class="border rounded-lg">
                        <div class="p-4 border-b">
                            <p><strong>From:</strong> <span class="phishing-clue" data-clue="sender">${
                              scenario.sender
                            }</span></p>
                            <p><strong>Subject:</strong> <span class="phishing-clue" data-clue="subject">${
                              scenario.subject
                            }</span></p>
                        </div>
                        <div class="p-4 text-gray-700">
                            <p class="mb-4 phishing-clue" data-clue="greeting">${scenario.greeting.replace(
                              "[Your Name]",
                              "Valued Student"
                            )}</p>
                            <p class="mb-6 phishing-clue" data-clue="body">${
                              scenario.body
                            }</p>
                            <div class="tooltip phishing-clue" data-clue="link">
                                <a href="#" onclick="event.preventDefault();" class="bg-blue-600 text-white px-5 py-2 rounded-lg hover:bg-blue-700">${
                                  scenario.linkText
                                }</a>
                                <span class="tooltiptext font-mono bg-gray-800 text-white text-xs rounded py-1 px-2">Link goes to: ${
                                  scenario.linkHref
                                }</span>
                            </div>
                        </div>
                    </div>
                    <div class="mt-6 text-center">
                        <p class="font-semibold mb-3">Is this email legitimate or a phishing attempt?</p>
                        <button class="bg-green-500 text-white px-6 py-2 rounded-lg hover:bg-green-600 mr-4" onclick="window.checkPhishingAnswer('legitimate')">Legitimate</button>
                        <button class="bg-red-500 text-white px-6 py-2 rounded-lg hover:bg-red-600" onclick="window.checkPhishingAnswer('phishing')">Phishing</button>
                    </div>
                </div>
                <div id="phishing-feedback" class="mt-6"></div>
            `;
        simulationContentEl.innerHTML = emailHTML;
        document
          .getElementById("back-to-simulations")
          .addEventListener("click", renderSimulationMenu);
      }

      function renderSimulationMenu() {
        currentChallenge = null;
        currentBreachScenario = null;
        simulationContentEl.innerHTML = `
                <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <!-- Cipher Challenge -->
                     <div class="simulation-card bg-white p-6 rounded-xl shadow-md hover:shadow-lg transition-shadow cursor-pointer" data-challenge="cipher">
                         <div class="flex items-center justify-center h-24 w-24 rounded-full bg-green-100 mx-auto mb-4"><i class="fas fa-user-secret text-4xl text-green-500"></i></div>
                        <h3 class="text-xl font-bold text-center mb-2">The Cipher Challenge</h3>
                        <p class="text-center text-sm mb-4">Decrypt hacker messages and stop their plans!</p>
                    </div>

                    <!-- Phishing -->
                    <div class="simulation-card bg-white p-6 rounded-xl shadow-md hover:shadow-lg transition-shadow cursor-pointer" data-challenge="phishing">
                        <div class="flex items-center justify-center h-24 w-24 rounded-full bg-red-100 mx-auto mb-4"><i class="fas fa-fish text-4xl text-red-500"></i></div>
                        <h3 class="text-xl font-bold text-center mb-2">The Phishing Challenge</h3>
                        <p class="text-gray-600 text-center text-sm mb-4">Can you spot the fake emails and websites?</p>
                        <div class="difficulty-selection hidden mt-4 space-y-2">
                             <button class="w-full bg-green-500 text-white py-2 rounded-lg font-semibold hover:bg-green-600" data-difficulty="easy">Easy</button>
                             <button class="w-full bg-yellow-500 text-white py-2 rounded-lg font-semibold hover:bg-yellow-600" data-difficulty="medium">Medium</button>
                             <button class="w-full bg-red-500 text-white py-2 rounded-lg font-semibold hover:bg-red-600" data-difficulty="hard">Hard</button>
                        </div>
                    </div>
                   
                    <!-- Data Breach -->
                    <div class="simulation-card bg-white p-6 rounded-xl shadow-md hover:shadow-lg transition-shadow cursor-pointer" data-challenge="breach">
                        <div class="flex items-center justify-center h-24 w-24 rounded-full bg-yellow-100 mx-auto mb-4"><i class="fas fa-exclamation-triangle text-4xl text-yellow-500"></i></div>
                        <h3 class="text-xl font-bold text-center mb-2">The Data Breach Drill</h3>
                        <p class="text-center text-sm mb-4">Make the right choices to secure your digital life.</p>
                         <div class="difficulty-selection hidden mt-4 space-y-2">
                             <button class="w-full bg-green-500 text-white py-2 rounded-lg font-semibold hover:bg-green-600" data-difficulty="easy">Easy</button>
                             <button class="w-full bg-yellow-500 text-white py-2 rounded-lg font-semibold hover:bg-yellow-600" data-difficulty="medium">Medium (Soon)</button>
                             <button class="w-full bg-red-500 text-white py-2 rounded-lg font-semibold hover:bg-red-600" data-difficulty="hard">Hard (Soon)</button>
                        </div>
                    </div>

                     <!-- Digital Footprint Detective -->
                    <div class="simulation-card bg-white p-6 rounded-xl shadow-md hover:shadow-lg transition-shadow cursor-pointer" data-challenge="footprint">
                         <div class="flex items-center justify-center h-24 w-24 rounded-full bg-blue-100 mx-auto mb-4"><i class="fas fa-user-secret text-4xl text-blue-500"></i></div>
                        <h3 class="text-xl font-bold text-center mb-2">Digital Footprint Detective</h3>
                        <p class="text-center text-sm mb-4">Find personal info from public social media posts.</p>
                    </div>
                </div>
            `;
      }

      window.checkPhishingAnswer = function (userAnswer) {
        const feedbackEl = document.getElementById("phishing-feedback");
        const isCorrect = userAnswer === currentChallenge.type;

        let feedbackHTML = "";
        if (isCorrect) {
          feedbackHTML = `
                    <div class="p-4 rounded-lg bg-green-100 border border-green-400 text-green-800">
                        <h4 class="font-bold">Correct!</h4>
                `;
          if (currentChallenge.type === "phishing") {
            feedbackHTML += `<p>You correctly identified this as a phishing attempt. Here are the clues you might have spotted:</p>
                        <ul class="list-disc list-inside mt-2 text-sm">
                            ${currentChallenge.redFlags
                              .map((flag) => `<li>${flag.explanation}</li>`)
                              .join("")}
                        </ul>
                    `;
          } else {
            feedbackHTML += `<p>You correctly identified this as a legitimate email. It came from a verified sender and the links point to the official website.</p>`;
          }
        } else {
          feedbackHTML = `
                    <div class="p-4 rounded-lg bg-red-100 border border-red-400 text-red-800">
                        <h4 class="font-bold">Not Quite!</h4>
                 `;
          if (currentChallenge.type === "phishing") {
            feedbackHTML += `<p>This was a phishing email. It can be tricky, but here are the red flags to look for:</p>
                        <ul class="list-disc list-inside mt-2 text-sm">
                            ${currentChallenge.redFlags
                              .map((flag) => `<li>${flag.explanation}</li>`)
                              .join("")}
                        </ul>
                    `;
          } else {
            feedbackHTML += `<p>This was actually a legitimate email. Phishers often try to mimic real emails, which makes spotting them a challenge.</p>`;
          }
        }

        feedbackHTML += `
                <button class="mt-4 bg-blue-600 text-white px-4 py-2 rounded-lg text-sm" onclick="document.getElementById('back-to-simulations').click()">Try another challenge</button>
                </div>
            `;
        feedbackEl.innerHTML = feedbackHTML;
        // Update score
        updateUserScore(isCorrect ? 20 : -10);
      };

      function startDataBreachChallenge(difficulty) {
        currentChallenge = null; // Clear phishing state
        // For now, we only have one scenario, but this is ready for more.
        const possibleScenarios = DATA_BREACH_SCENARIOS.filter(
          (s) => s.difficulty === difficulty
        );
        currentBreachScenario = possibleScenarios[0];
        currentBreachNodeKey = currentBreachScenario.startNode;
        userScore = 0;
        answeredChoices.clear();
        renderDataBreachStep(currentBreachNodeKey);
      }

      function renderDataBreachStep(nodeKey) {
        const node = currentBreachScenario.nodes[nodeKey];

        if (node.end) {
          renderDataBreachEnd(node);
          return;
        }

        let choicesHTML = "";
        node.choices.forEach((choice, index) => {
          const choiceId = `${nodeKey}-choice-${index}`;
          const isDisabled = answeredChoices.has(choiceId);
          choicesHTML += `<button id="${choiceId}" class="w-full text-left p-4 rounded-lg border-2 ${
            isDisabled
              ? "bg-gray-200 text-gray-500 cursor-not-allowed"
              : "bg-gray-100 hover:bg-blue-100 border-transparent focus:border-blue-500 focus:outline-none"
          }" onclick="window.checkDataBreachAnswer(${index})" ${
            isDisabled ? "disabled" : ""
          }>${choice.text}</button>`;
        });

        const breachHTML = `
                <div class="bg-white p-8 rounded-xl shadow-md max-w-2xl mx-auto">
                    <div class="flex justify-between items-center mb-4">
                        <button id="back-to-simulations" class="text-sm text-blue-600 hover:underline">&larr; Back to Challenges</button>
                        <div class="text-xl font-bold text-indigo-600">Score: <span id="score-display">${userScore}</span></div>
                    </div>
                    <h3 class="text-2xl font-bold mb-4">${currentBreachScenario.title}</h3>
                    <p class="text-gray-700 mb-6">${node.text}</p>
                    <div id="breach-feedback" class="mb-4"></div>
                    <div class="space-y-4">
                        ${choicesHTML}
                    </div>
                </div>
            `;
        simulationContentEl.innerHTML = breachHTML;
        document
          .getElementById("back-to-simulations")
          .addEventListener("click", renderSimulationMenu);
      }

      window.checkDataBreachAnswer = function (choiceIndex) {
        const feedbackEl = document.getElementById("breach-feedback");
        const node = currentBreachScenario.nodes[currentBreachNodeKey];
        const choice = node.choices[choiceIndex];
        const choiceId = `${currentBreachNodeKey}-choice-${choiceIndex}`;

        if (choice.next) {
          // Correct answer
          userScore += 25;
          document.getElementById("score-display").textContent = userScore;
          feedbackEl.innerHTML = `<div class="p-3 rounded-lg bg-green-100 text-green-800 font-medium">Correct! +25 points. Proceeding to the next step...</div>`;

          // Disable all buttons during transition
          const buttons = document.querySelectorAll(".space-y-4 button");
          buttons.forEach((button) => (button.disabled = true));

          setTimeout(() => {
            currentBreachNodeKey = choice.next;
            answeredChoices.clear(); // Clear answered choices for the new step
            renderDataBreachStep(currentBreachNodeKey);
          }, 2000);
        } else {
          // Incorrect answer
          userScore -= 10;
          document.getElementById("score-display").textContent = userScore;
          feedbackEl.innerHTML = `<div class="p-3 rounded-lg bg-red-100 text-red-800 font-medium"><b>Incorrect (-10 points):</b> ${choice.explanation} Please try again.</div>`;

          // Disable the wrong choice
          answeredChoices.add(choiceId);
          document.getElementById(choiceId).disabled = true;
          document
            .getElementById(choiceId)
            .classList.add(
              "bg-gray-200",
              "text-gray-500",
              "cursor-not-allowed"
            );
          document
            .getElementById(choiceId)
            .classList.remove("bg-gray-100", "hover:bg-blue-100");
        }
      };

      function renderDataBreachEnd(node) {
        const endHTML = `
                <div class="bg-white p-8 rounded-xl shadow-md max-w-2xl mx-auto text-center">
                    <i class="fas ${
                      node.success
                        ? "fa-check-circle text-green-500"
                        : "fa-times-circle text-red-500"
                    } text-6xl mb-4"></i>
                    <h3 class="text-3xl font-bold mb-4">${node.title}</h3>
                    <p class="text-gray-700 mb-6">${node.text}</p>
                    <div class="my-6">
                        <p class="text-lg text-gray-600">Final Score</p>
                        <p class="text-5xl font-bold text-indigo-600">${userScore}</p>
                    </div>
                    <button id="back-to-simulations" class="bg-blue-600 text-white px-6 py-3 rounded-lg font-semibold hover:bg-blue-700">Play Again</button>
                </div>
            `;
        simulationContentEl.innerHTML = endHTML;
        document
          .getElementById("back-to-simulations")
          .addEventListener("click", renderSimulationMenu);
        // Update final score
        if (userScore > 0) {
          updateUserScore(userScore);
        }
      }

      function startDigitalFootprintChallenge() {
        // Reset the scenario
        for (const key in DIGITAL_FOOTPRINT_SCENARIO.clues) {
          DIGITAL_FOOTPRINT_SCENARIO.clues[key].found = false;
        }
        renderDigitalFootprintChallenge();
      }

      function renderDigitalFootprintChallenge() {
        const scenario = DIGITAL_FOOTPRINT_SCENARIO;
        let postsHTML = "";
        scenario.posts
          .slice()
          .reverse()
          .forEach((post) => {
            // Show newest posts first
            postsHTML += `
                    <div class="post-card bg-white p-4 rounded-lg shadow flex space-x-4 ${
                      post.clueType
                        ? "cursor-pointer hover:ring-2 hover:ring-blue-500 transition-all"
                        : ""
                    }" data-post-id="${post.id}">
                        <img src="${
                          post.avatar
                        }" alt="avatar" class="w-12 h-12 rounded-full flex-shrink-0">
                        <div>
                            <p class="font-bold">${post.author}</p>
                            <p class="text-sm text-gray-500">${post.date}</p>
                            <p class="mt-2 text-gray-800">${post.text}</p>
                            ${
                              post.image
                                ? `<img src="${post.image}" class="mt-2 rounded-lg border">`
                                : ""
                            }
                        </div>
                    </div>
                `;
          });

        let notepadHTML = "";
        for (const key in scenario.clues) {
          const clue = scenario.clues[key];
          notepadHTML += `
                    <div class="flex items-center">
                         <i class="fas ${
                           clue.found
                             ? "fa-check-circle text-green-500"
                             : "fa-question-circle text-gray-400"
                         } mr-3"></i>
                        <div>
                            <p class="font-semibold text-sm">${clue.label}</p>
                            <p class="font-mono text-indigo-700">${
                              clue.found ? clue.answer : "???"
                            }</p>
                        </div>
                    </div>
                `;
        }

        const allFound = Object.values(scenario.clues).every((c) => c.found);

        const footprintHTML = `
                <div class="grid grid-cols-1 lg:grid-cols-3 gap-8">
                    <div class="lg:col-span-2">
                        <div class="flex justify-between items-center mb-4">
                             <button id="back-to-simulations" class="text-sm text-blue-600 hover:underline">&larr; Back to Challenges</button>
                             <h3 class="text-2xl font-bold text-center">Find The Clues</h3>
                             <div></div>
                        </div>
                        <p class="text-center text-gray-600 mb-4">Click on the social media posts below to find clues about <span class="font-bold">${
                          scenario.target
                        }</span>.</p>
                        <div id="social-feed" class="space-y-4">
                            ${postsHTML}
                        </div>
                    </div>
                    <div class="bg-yellow-50 p-6 rounded-xl shadow-lg border-2 border-yellow-200">
                        <h4 class="text-xl font-bold mb-4 flex items-center"><i class="fas fa-clipboard mr-2"></i> Detective's Notepad</h4>
                        <div id="notepad" class="space-y-4">
                            ${notepadHTML}
                        </div>
                         <div id="clue-feedback" class="mt-4 text-sm p-3 rounded-lg bg-blue-50 border border-blue-200 text-blue-800 min-h-[60px]">
                            Click a post to reveal a clue...
                        </div>
                        ${
                          allFound
                            ? `<div class="mt-4 text-center">
                           <button id="reveal-attack-btn" class="w-full bg-red-600 text-white font-bold py-3 rounded-lg hover:bg-red-700 transition-transform transform hover:scale-105">
                                See How This Info Could Be Used
                           </button>
                        </div>`
                            : ""
                        }
                    </div>
                </div>
            `;
        simulationContentEl.innerHTML = footprintHTML;
        document
          .getElementById("back-to-simulations")
          .addEventListener("click", renderSimulationMenu);
        if (allFound) {
          document
            .getElementById("reveal-attack-btn")
            .addEventListener("click", renderFootprintReveal);
        }
      }

      function renderFootprintReveal() {
        const scenario = DIGITAL_FOOTPRINT_SCENARIO;
        let attackVectorsHTML = "";

        for (const key in scenario.clues) {
          const clue = scenario.clues[key];
          attackVectorsHTML += `
                     <div class="bg-gray-100 p-4 rounded-lg">
                        <h5 class="font-bold text-lg text-gray-800">${clue.label}: <span class="font-mono text-red-600">${clue.answer}</span></h5>
                        <p class="text-gray-700 mt-1">${clue.attackVector}</p>
                    </div>
                `;
        }

        const revealHTML = `
                <div class="bg-white p-8 rounded-xl shadow-2xl max-w-3xl mx-auto border-4 border-red-500">
                    <div class="text-center">
                        <i class="fas fa-exclamation-triangle text-6xl text-red-500 mb-4"></i>
                        <h3 class="text-3xl font-bold text-red-700">Attacker's Playbook</h3>
                        <p class="text-gray-600 mt-2">You found the clues. Here’s how a real attacker would use them against you.</p>
                    </div>
                    <div class="mt-6 space-y-4">
                       ${attackVectorsHTML}
                    </div>
                    <div class="mt-8 text-center p-4 bg-blue-50 rounded-lg">
                         <h4 class="font-bold text-blue-800">The Lesson</h4>
                         <p class="text-blue-700">Seemingly innocent posts can be combined to build a powerful profile for identity theft. Be mindful of what you and your friends share online. Your privacy is your first line of defense.</p>
                    </div>
                    <div class="text-center mt-6">
                        <button id="back-to-simulations" class="bg-blue-600 text-white px-6 py-3 rounded-lg font-semibold hover:bg-blue-700">I Understand</button>
                    </div>
                </div>
            `;
        simulationContentEl.innerHTML = revealHTML;
        document
          .getElementById("back-to-simulations")
          .addEventListener("click", renderSimulationMenu);
        // Update score for completing the mission
        const score = Object.keys(scenario.clues).length * 15;
        updateUserScore(score);
      }

      function startCipherChallenge() {
        // Build a new mission with one random question from each category
        CIPHER_CHALLENGE.currentMissionLevels = [
          CIPHER_CHALLENGE.questionBank.caesar[
            Math.floor(
              Math.random() * CIPHER_CHALLENGE.questionBank.caesar.length
            )
          ],
          CIPHER_CHALLENGE.questionBank.atbash[
            Math.floor(
              Math.random() * CIPHER_CHALLENGE.questionBank.atbash.length
            )
          ],
          CIPHER_CHALLENGE.questionBank.keyword[
            Math.floor(
              Math.random() * CIPHER_CHALLENGE.questionBank.keyword.length
            )
          ],
        ];
        // Add the cipher type to each level object for easy reference
        CIPHER_CHALLENGE.currentMissionLevels[0].cipherType = "Caesar";
        CIPHER_CHALLENGE.currentMissionLevels[1].cipherType = "Atbash";
        CIPHER_CHALLENGE.currentMissionLevels[2].cipherType = "Keyword";

        CIPHER_CHALLENGE.currentLevelIndex = 0;
        userScore = 0; // Reset score for the mission
        renderCipherLevel();
      }

      function renderCipherLevel() {
        const level =
          CIPHER_CHALLENGE.currentMissionLevels[
            CIPHER_CHALLENGE.currentLevelIndex
          ];

        const cipherHTML = `
                <div class="bg-gray-800 text-white font-mono p-8 rounded-xl shadow-lg max-w-3xl mx-auto border-4 border-green-500">
                     <button id="back-to-simulations" class="mb-4 text-sm text-green-400 hover:underline font-sans">&larr; Abort Mission</button>
                    <h3 class="text-2xl font-bold text-green-400 text-center mb-2">${
                      CIPHER_CHALLENGE.title
                    }</h3>
                    <p class="text-center text-gray-400 mb-6 font-sans">Level ${
                      CIPHER_CHALLENGE.currentLevelIndex + 1
                    } of ${
          CIPHER_CHALLENGE.currentMissionLevels.length
        } | Score: <span id="cipher-score">${userScore}</span></p>
                    
                    <div class="bg-black p-4 rounded-md">
                        <p class="text-gray-400">> Incoming Transmission...</p>
                        <p class="text-green-500 text-xl whitespace-pre-wrap">${
                          level.encrypted
                        }</p>
                    </div>

                     <div id="cipher-feedback" class="my-4"></div>

                    <div class="mt-6">
                        <label for="decrypted-text" class="block text-green-400 mb-2">> Enter Decrypted Message:</label>
                        <textarea id="decrypted-text" rows="3" class="w-full bg-gray-900 text-white p-2 rounded-md border border-gray-600 focus:border-green-500 focus:outline-none"></textarea>
                    </div>

                    <div id="cipher-controls" class="mt-4 flex justify-between items-center">
                        <div>
                            <button class="font-sans bg-gray-600 text-white py-2 px-4 rounded hover:bg-gray-500 text-sm" onclick="window.showCipherClue()">Get a Clue</button>
                            <button class="font-sans bg-blue-600 text-white py-2 px-4 rounded hover:bg-blue-500 text-sm ml-2" onclick="window.showCipherExplanation()">Learn about this Cipher</button>
                        </div>
                        <div>
                            <button class="font-sans bg-yellow-500 text-black py-2 px-4 rounded hover:bg-yellow-400 text-sm" onclick="window.showCipherAnswer()">Show Answer</button>
                            <button class="font-sans bg-green-500 text-black font-bold py-2 px-6 rounded hover:bg-green-400 ml-2" onclick="window.checkCipherAnswer()">Decrypt</button>
                        </div>
                    </div>
                </div>
            `;
        simulationContentEl.innerHTML = cipherHTML;
        document
          .getElementById("back-to-simulations")
          .addEventListener("click", renderSimulationMenu);
      }

      window.showCipherExplanation = function () {
        const level =
          CIPHER_CHALLENGE.currentMissionLevels[
            CIPHER_CHALLENGE.currentLevelIndex
          ];
        const explanation = CIPHER_EXPLANATIONS[level.cipherType];
        if (!explanation) return;

        document.getElementById("cipher-learn-title").textContent =
          explanation.title;
        document.getElementById("cipher-learn-explanation").textContent =
          explanation.explanation;
        document.getElementById("cipher-learn-example").innerHTML =
          explanation.example;
        document.getElementById("cipher-learn-weakness").innerHTML =
          explanation.weakness;
        cipherLearnModal.classList.remove("hidden");
      };

      window.showCipherClue = function () {
        const level =
          CIPHER_CHALLENGE.currentMissionLevels[
            CIPHER_CHALLENGE.currentLevelIndex
          ];
        const feedbackEl = document.getElementById("cipher-feedback");
        feedbackEl.innerHTML = `
                <div class="p-4 rounded-md bg-yellow-900 bg-opacity-50 text-yellow-300 border border-yellow-500">
                    <b class="font-bold">HINT (-10pts):</b> ${level.clue}
                </div>`;
        userScore -= 10;
        document.getElementById("cipher-score").textContent = userScore;
      };

      window.showCipherAnswer = function () {
        const level =
          CIPHER_CHALLENGE.currentMissionLevels[
            CIPHER_CHALLENGE.currentLevelIndex
          ];
        const feedbackEl = document.getElementById("cipher-feedback");
        const controlsEl = document.getElementById("cipher-controls");

        document.getElementById("decrypted-text").value = level.decrypted;
        feedbackEl.innerHTML = `
                <div class="p-4 rounded-md bg-blue-900 bg-opacity-50 text-blue-300 border border-blue-500">
                    <b class="font-bold">Answer Revealed (-20pts):</b> The correct decryption is shown above.
                </div>`;

        userScore -= 20;
        document.getElementById("cipher-score").textContent = userScore;

        const nextButtonLabel =
          CIPHER_CHALLENGE.currentLevelIndex <
          CIPHER_CHALLENGE.currentMissionLevels.length - 1
            ? "Next Level"
            : "Finish Mission";
        controlsEl.innerHTML = `<button class="w-full font-sans bg-blue-600 text-white font-bold py-3 rounded hover:bg-blue-500" onclick="window.forceNextCipherLevel()">${nextButtonLabel}</button>`;
      };

      window.forceNextCipherLevel = function () {
        CIPHER_CHALLENGE.currentLevelIndex++;
        if (
          CIPHER_CHALLENGE.currentLevelIndex >=
          CIPHER_CHALLENGE.currentMissionLevels.length
        ) {
          renderCipherWin();
        } else {
          renderCipherLevel();
        }
      };

      window.checkCipherAnswer = function () {
        const level =
          CIPHER_CHALLENGE.currentMissionLevels[
            CIPHER_CHALLENGE.currentLevelIndex
          ];
        const userAnswer = document
          .getElementById("decrypted-text")
          .value.trim()
          .toUpperCase();
        const feedbackEl = document.getElementById("cipher-feedback");

        if (userAnswer === level.decrypted) {
          userScore += 50; // Award points for correct answer
          document.getElementById("cipher-score").textContent = userScore;

          CIPHER_CHALLENGE.currentLevelIndex++;
          if (
            CIPHER_CHALLENGE.currentLevelIndex >=
            CIPHER_CHALLENGE.currentMissionLevels.length
          ) {
            renderCipherWin();
          } else {
            feedbackEl.innerHTML = `
                        <div class="p-4 rounded-md bg-green-900 bg-opacity-50 text-green-300 border border-green-500">
                            <b class="font-bold">SUCCESS!</b> Decryption complete. Intercepting next message...
                        </div>`;
            setTimeout(renderCipherLevel, 2000);
          }
        } else {
          feedbackEl.innerHTML = `
                    <div class="p-4 rounded-md bg-red-900 bg-opacity-50 text-red-300 border border-red-500">
                        <b class="font-bold">ERROR:</b> Decryption failed. Check your logic and try again.
                    </div>`;
        }
      };

      function renderCipherWin() {
        const winHTML = `
                 <div class="bg-gray-800 text-white font-mono p-8 rounded-xl shadow-lg max-w-3xl mx-auto border-4 border-blue-500 text-center">
                    <i class="fas fa-trophy text-6xl text-yellow-400 mb-4"></i>
                    <h3 class="text-3xl font-bold text-blue-400 font-sans">Mission Accomplished!</h3>
                    <p class="mt-2 text-gray-300 font-sans">You decrypted all the messages and uncovered the hackers' plan to cover the mascot statue in glitter. The campus is safe, thanks to you!</p>
                    <p class="font-sans text-xl mt-4">Final Score: <span class="font-bold text-yellow-400">${userScore}</span></p>
                    <button id="back-to-simulations" class="mt-6 bg-blue-600 text-white font-sans font-semibold px-6 py-3 rounded-lg hover:bg-blue-700">Return to HQ</button>
                 </div>
            `;
        simulationContentEl.innerHTML = winHTML;
        document
          .getElementById("back-to-simulations")
          .addEventListener("click", renderSimulationMenu);
        // Update final score to leaderboard
        if (userScore > 0) {
          updateUserScore(userScore);
        }
      }

      // --- Simulation Menu Logic ---
      simulationSection.addEventListener("click", (e) => {
        const card = e.target.closest(".simulation-card");
        if (!card) {
          // Handle clicks inside the simulation, like on a post
          const post = e.target.closest(".post-card");
          if (post && post.dataset.postId) {
            const postId = parseInt(post.dataset.postId);
            const scenarioPost = DIGITAL_FOOTPRINT_SCENARIO.posts.find(
              (p) => p.id === postId
            );
            if (scenarioPost && scenarioPost.clueType) {
              DIGITAL_FOOTPRINT_SCENARIO.clues[
                scenarioPost.clueType
              ].found = true;
              document.getElementById(
                "clue-feedback"
              ).innerHTML = `<p><b class="font-semibold">Clue Found!</b> ${scenarioPost.clueDetail}</p>`;
              renderDigitalFootprintChallenge(); // Re-render to update the notepad
            }
          }
          return;
        }

        const challenge = card.dataset.challenge;

        if (challenge === "phishing" || challenge === "breach") {
          const difficultySelection = card.querySelector(
            ".difficulty-selection"
          );
          if (difficultySelection) {
            difficultySelection.classList.toggle("hidden");
          }
        } else if (challenge === "footprint") {
          startDigitalFootprintChallenge();
        } else if (challenge === "cipher") {
          startCipherChallenge();
        }

        const difficultyBtn = e.target.closest("button[data-difficulty]");
        if (difficultyBtn) {
          const difficulty = difficultyBtn.dataset.difficulty;
          const parentCard = difficultyBtn.closest(".simulation-card");
          const challengeType = parentCard.dataset.challenge;

          if (challengeType === "phishing") {
            startPhishingChallenge(difficulty);
          } else if (challengeType === "breach" && difficulty === "easy") {
            // Only easy is enabled for now
            startDataBreachChallenge(difficulty);
          }
        }
      });

      // Cipher Learn Modal Listeners
      cipherLearnCloseBtn.addEventListener("click", () =>
        cipherLearnModal.classList.add("hidden")
      );
      cipherLearnModal.addEventListener("click", (e) => {
        if (e.target === cipherLearnModal) {
          cipherLearnModal.classList.add("hidden");
        }
      });

      // --- Forum Logic ---
      newPostBtn.addEventListener("click", () =>
        newPostModal.classList.remove("hidden")
      );
      cancelPostBtn.addEventListener("click", () =>
        newPostModal.classList.add("hidden")
      );
      newPostModal.addEventListener("click", (e) => {
        if (e.target === newPostModal) newPostModal.classList.add("hidden");
      });

      newPostForm.addEventListener("submit", async (e) => {
        e.preventDefault();
        if (!userId) return;

        const title = document.getElementById("post-title").value;
        const content = document.getElementById("post-content").value;

        try {
          const postsCol = collection(
            db,
            `artifacts/${appId}/public/data/forums`
          );
          await addDoc(postsCol, {
            title,
            content,
            authorId: userId,
            authorName: `Agent-${userId.substring(0, 6)}`,
            createdAt: serverTimestamp(),
            replyCount: 0,
          });
          newPostForm.reset();
          newPostModal.classList.add("hidden");
        } catch (error) {
          console.error("Error creating new post:", error);
        }
      });

      forumSearchInput.addEventListener("input", () => {
        const searchTerm = forumSearchInput.value.toLowerCase().trim();
        if (searchTerm === "") {
          renderForumList(allForumPosts);
          return;
        }
        const filteredPosts = allForumPosts.filter(
          (post) =>
            post.title.toLowerCase().includes(searchTerm) ||
            post.content.toLowerCase().includes(searchTerm)
        );
        renderForumList(filteredPosts, true); // Pass true to indicate it's a search result
      });

      function renderForumList(posts, isSearchResult = false) {
        forumPostsContainer.innerHTML = "";
        if (posts.length === 0) {
          const message = isSearchResult
            ? `No discussions found matching your search.`
            : `No discussions yet. Be the first to start one!`;
          forumPostsContainer.innerHTML = `<p class="text-center text-gray-500 p-8">${message}</p>`;
          return;
        }
        posts.forEach((post) => {
          const postEl = document.createElement("div");
          postEl.className =
            "bg-white p-4 rounded-lg shadow-sm hover:shadow-md transition-shadow cursor-pointer";
          postEl.dataset.postId = post.id;
          postEl.innerHTML = `
                    <h4 class="font-bold text-lg text-indigo-700">${
                      post.title
                    }</h4>
                    <p class="text-sm text-gray-500">By ${post.authorName} on ${
            post.createdAt
              ? post.createdAt.toDate().toLocaleDateString()
              : "just now"
          }</p>
                    <p class="text-gray-600 mt-2 truncate">${post.content}</p>
                    <div class="text-sm text-gray-500 mt-2">${
                      post.replyCount || 0
                    } replies</div>
                `;
          postEl.addEventListener("click", () => showPostView(post.id));
          forumPostsContainer.appendChild(postEl);
        });
      }

      function showPostView(postId) {
        forumListView.classList.add("hidden");
        forumPostView.classList.remove("hidden");
        renderPostView(postId);
        listenForReplies(postId);
      }

      function showForumListView() {
        if (unsubscribeReplies) unsubscribeReplies();
        forumListView.classList.remove("hidden");
        forumPostView.classList.add("hidden");
        forumPostView.innerHTML = "";
      }

      async function renderPostView(postId) {
        try {
          const postRef = doc(
            db,
            `artifacts/${appId}/public/data/forums`,
            postId
          );
          const postSnap = await getDoc(postRef);
          if (!postSnap.exists()) {
            forumPostView.innerHTML = `<p>Post not found.</p><button onclick="showForumListView()">Back to list</button>`;
            return;
          }
          const post = postSnap.data();

          forumPostView.innerHTML = `
                    <div class="bg-white p-8 rounded-xl shadow-md">
                        <button class="mb-6 text-sm text-blue-600 hover:underline" onclick="window.showForumListView()">&larr; Back to All Discussions</button>
                        <h2 class="text-3xl font-bold">${post.title}</h2>
                        <p class="text-sm text-gray-500 mt-1">By ${
                          post.authorName
                        } on ${post.createdAt.toDate().toLocaleDateString()}</p>
                        <p class="mt-6 text-gray-800 whitespace-pre-wrap">${
                          post.content
                        }</p>
                    </div>
                    <div id="replies-container" class="mt-6 space-y-4"></div>
                    <div class="mt-6">
                        <form id="reply-form" class="bg-white p-4 rounded-xl shadow-md">
                             <h4 class="font-bold mb-2">Leave a Reply</h4>
                             <textarea id="reply-content" rows="4" class="w-full p-2 border-2 border-gray-300 rounded-lg" placeholder="Share your thoughts..." required></textarea>
                             <div class="text-right mt-2">
                                <button type="submit" class="bg-green-600 text-white font-semibold px-5 py-2 rounded-lg hover:bg-green-700">Submit Reply</button>
                             </div>
                        </form>
                    </div>
                `;

          // Add reply form listener
          document
            .getElementById("reply-form")
            .addEventListener("submit", async (e) => {
              e.preventDefault();
              const content = document.getElementById("reply-content").value;
              if (content.trim() === "" || !userId) return;

              const repliesCol = collection(
                db,
                `artifacts/${appId}/public/data/forums/${postId}/replies`
              );
              await addDoc(repliesCol, {
                content,
                authorId: userId,
                authorName: `Agent-${userId.substring(0, 6)}`,
                createdAt: serverTimestamp(),
              });

              // Also update reply count on main post
              const currentCount = post.replyCount || 0;
              await updateDoc(postRef, { replyCount: currentCount + 1 });

              document.getElementById("reply-content").value = "";
            });
        } catch (err) {
          console.error("Error rendering post view:", err);
        }
      }

      function listenForReplies(postId) {
        if (unsubscribeReplies) unsubscribeReplies();

        const repliesCol = collection(
          db,
          `artifacts/${appId}/public/data/forums/${postId}/replies`
        );
        const q = query(repliesCol, orderBy("createdAt", "asc"));

        unsubscribeReplies = onSnapshot(q, (snapshot) => {
          const repliesContainer = document.getElementById("replies-container");
          repliesContainer.innerHTML =
            '<h3 class="text-xl font-bold mb-4">Replies</h3>';
          if (snapshot.empty) {
            repliesContainer.innerHTML +=
              '<p class="text-gray-500">No replies yet.</p>';
          }
          snapshot.docs.forEach((doc) => {
            const reply = doc.data();
            const replyEl = document.createElement("div");
            replyEl.className = "bg-white p-4 rounded-lg shadow-sm";
            replyEl.innerHTML = `
                        <p class="text-gray-800">${reply.content}</p>
                        <p class="text-xs text-gray-500 mt-2">By ${
                          reply.authorName
                        } on ${
              reply.createdAt
                ? reply.createdAt.toDate().toLocaleDateString()
                : "just now"
            }</p>
                    `;
            repliesContainer.appendChild(replyEl);
          });
        });
      }

      function listenForForumPosts() {
        if (unsubscribeForum) unsubscribeForum();

        const postsCol = collection(
          db,
          `artifacts/${appId}/public/data/forums`
        );
        const q = query(postsCol, orderBy("createdAt", "desc"));

        unsubscribeForum = onSnapshot(q, (snapshot) => {
          allForumPosts = snapshot.docs.map((doc) => ({
            id: doc.id,
            ...doc.data(),
          }));
          renderForumList(allForumPosts);
        });
      }
      window.showForumListView = showForumListView;

      // --- Firestore Real-time Listener ---

      async function updateUserScore(pointsToAdd) {
        if (!userId) return;
        const userRef = doc(
          db,
          `artifacts/${appId}/public/data/leaderboard`,
          userId
        );

        try {
          const userDoc = await getDoc(userRef);
          let currentScore = 0;
          if (userDoc.exists()) {
            currentScore = userDoc.data().score || 0;
          }

          const newScore = currentScore + pointsToAdd;

          await setDoc(
            userRef,
            {
              score: newScore,
              username: `Agent-${userId.substring(0, 6)}`, // Create a display name
            },
            { merge: true }
          );
        } catch (error) {
          console.error("Error updating user score:", error);
        }
      }

      function renderLeaderboard(allUsers) {
        const leaderboardBody = document.getElementById("leaderboard-body");
        const userRankContainer = document.getElementById(
          "user-rank-container"
        );
        leaderboardBody.innerHTML = ""; // Clear existing

        const sortedUsers = [...allUsers].sort((a, b) => b.score - a.score);

        // Render top 10
        const top10 = sortedUsers.slice(0, 10);
        top10.forEach((user, index) => {
          const rank = index + 1;
          const row = document.createElement("tr");
          row.className = `border-b ${
            user.id === userId ? "bg-indigo-100 font-bold" : ""
          }`;
          row.innerHTML = `
                    <td class="p-2">${rank}</td>
                    <td class="p-2">${user.username}</td>
                    <td class="p-2">${user.score.toLocaleString()}</td>
                `;
          leaderboardBody.appendChild(row);
        });

        // Find and display current user's rank
        const currentUserRankIndex = sortedUsers.findIndex(
          (u) => u.id === userId
        );
        if (currentUserRankIndex !== -1) {
          const currentUserData = sortedUsers[currentUserRankIndex];
          document.getElementById("user-rank").textContent = `#${
            currentUserRankIndex + 1
          }`;
          document.getElementById("user-score").textContent =
            currentUserData.score.toLocaleString();
          userRankContainer.classList.remove("hidden");
        } else {
          userRankContainer.classList.add("hidden");
        }
      }

      function listenForLeaderboard() {
        const leaderboardCol = collection(
          db,
          `artifacts/${appId}/public/data/leaderboard`
        );

        if (unsubscribeLeaderboard) unsubscribeLeaderboard(); // Detach old listener

        unsubscribeLeaderboard = onSnapshot(
          leaderboardCol,
          (snapshot) => {
            const allUsers = snapshot.docs.map((doc) => ({
              id: doc.id,
              ...doc.data(),
            }));
            renderLeaderboard(allUsers);
          },
          (error) => {
            console.error("Error listening to leaderboard:", error);
            document.getElementById(
              "leaderboard-body"
            ).innerHTML = `<tr><td colspan="3" class="text-center p-8 text-red-500">Could not load leaderboard.</td></tr>`;
          }
        );
      }

      function listenForPasswords(uid) {
        userId = uid;
        console.log(`Listening for passwords for user: ${userId}`);
        const passwordsCollection = collection(
          db,
          `artifacts/${appId}/users/${userId}/passwords`
        );

        // Detach previous listener if it exists
        if (unsubscribePasswords) {
          unsubscribePasswords();
        }

        unsubscribePasswords = onSnapshot(
          passwordsCollection,
          (snapshot) => {
            passwords = snapshot.docs.map((doc) => ({
              id: doc.id,
              ...doc.data(),
            }));
            renderPasswords();
            updateDashboard();
          },
          (error) => {
            console.error("Error listening for password updates: ", error);
          }
        );
      }

      // --- Auth Initialization ---
      async function initAuth() {
        onAuthStateChanged(auth, async (user) => {
          if (user) {
            console.log("User is signed in with UID:", user.uid);
            userId = user.uid;
            listenForPasswords(user.uid);
            listenForLeaderboard(); // Start listening for leaderboard data
            listenForForumPosts(); // Start listening for forum data
          } else {
            console.log("User is not signed in, attempting anonymous sign-in.");
            if (unsubscribePasswords) unsubscribePasswords(); // Stop listening
            if (unsubscribeLeaderboard) unsubscribeLeaderboard();
            if (unsubscribeForum) unsubscribeForum();
            passwords = [];
            renderPasswords();
            updateDashboard();

            try {
              if (
                typeof __initial_auth_token !== "undefined" &&
                __initial_auth_token
              ) {
                console.log("Attempting sign in with custom token.");
                await signInWithCustomToken(auth, __initial_auth_token);
              } else {
                console.log("Attempting anonymous sign in.");
                await signInAnonymously(auth);
              }
            } catch (error) {
              console.error("Sign-in failed:", error);
            }
          }
        });
      }

      // --- Initial Load ---
      function initApp() {
        // Display a random security tip on load
        const tipEl = document.getElementById("security-tip");
        const randomTip =
          SECURITY_TIPS[Math.floor(Math.random() * SECURITY_TIPS.length)];
        tipEl.textContent = randomTip;

        // Handle initial page load and subsequent hash changes
        handleHashChange();
        window.addEventListener("hashchange", handleHashChange);

        renderSimulationMenu(); // Render the initial simulation menu
        generatePassword();
        initAuth(); // Start the authentication process
      }

      initApp();
