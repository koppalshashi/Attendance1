// 🌐 lang.js — Automatic page translation

// 1️⃣ Detect user's preferred language (default English)
const userLang = navigator.language || navigator.userLanguage;
const langCode = userLang.split('-')[0]; // e.g. "kn" for Kannada, "hi" for Hindi, etc.

console.log("Detected language:", langCode);

// 2️⃣ Supported languages
const supportedLangs = ['en', 'kn', 'hi']; // you can add more like 'ta', 'te', etc.

async function translateText(text, lang) {
  try {
    const response = await fetch(`/api/translate?text=${encodeURIComponent(text)}&lang=${lang}`);
    const data = await response.json();
    return data.translatedText || text;
  } catch (err) {
    console.error("Translation failed for:", text, err);
    return text; // fallback to original
  }
}

// 3️⃣ Translate all visible text on the page
async function autoTranslatePage() {
  if (langCode === 'en' || !supportedLangs.includes(langCode)) {
    console.log("No translation needed for language:", langCode);
    return;
  }

  // Get all elements with text
  const textElements = document.querySelectorAll('h1, h2, h3, h4, h5, h6, p, label, button, a, span, th, td, option');

  for (let el of textElements) {
    const originalText = el.innerText.trim();
    if (originalText.length > 0) {
      const translated = await translateText(originalText, langCode);
      el.innerText = translated;
    }
  }

  console.log(`✅ Page translated automatically to ${langCode}`);
}

// 4️⃣ Run translation after page loads
window.addEventListener('DOMContentLoaded', autoTranslatePage);
