/**
 * Phishing Website Detection System
 * Frontend Client Controller & AJAX Request Handler
 */

document.addEventListener("DOMContentLoaded", () => {
    const urlInput = document.getElementById("urlInput");
    
    // Auto-hide error alert when typing
    urlInput.addEventListener("input", () => {
        hideError();
    });
});

/**
 * Populate input with quick test example and immediately analyze
 */
function setSample(sampleUrl) {
    const urlInput = document.getElementById("urlInput");
    urlInput.value = sampleUrl;
    hideError();
    scanUrl();
}

/**
 * Clear the input field and reset focus
 */
function clearInput() {
    const urlInput = document.getElementById("urlInput");
    urlInput.value = "";
    hideError();
    urlInput.focus();
}

/**
 * Show error notification banner
 */
function showError(message) {
    const errorAlert = document.getElementById("errorAlert");
    const errorMessage = document.getElementById("errorMessage");
    errorMessage.textContent = message;
    errorAlert.style.display = "flex";
}

/**
 * Hide error notification banner
 */
function hideError() {
    const errorAlert = document.getElementById("errorAlert");
    errorAlert.style.display = "none";
}

/**
 * Set loading state on scan button
 */
function setLoading(isLoading) {
    const checkBtn = document.getElementById("checkBtn");
    const btnText = checkBtn.querySelector(".btn-text");
    const btnLoader = checkBtn.querySelector(".btn-loader");
    
    if (isLoading) {
        checkBtn.disabled = true;
        btnText.style.display = "none";
        btnLoader.style.display = "inline-flex";
    } else {
        checkBtn.disabled = false;
        btnText.style.display = "inline-flex";
        btnLoader.style.display = "none";
    }
}

/**
 * Main URL scanning function
 * Dispatches async POST request to Flask backend endpoint
 */
async function scanUrl() {
    const urlInput = document.getElementById("urlInput");
    const rawUrl = urlInput.value.trim();

    // Client-side validation
    if (!rawUrl) {
        showError("Please enter a valid website URL to scan.");
        urlInput.focus();
        return;
    }

    hideError();
    setLoading(true);

    try {
        const response = await fetch("/predict", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ url: rawUrl })
        });

        const data = await response.json();

        if (!response.ok || !data.success) {
            showError(data.error || "An error occurred while inspecting the URL.");
            setLoading(false);
            return;
        }

        // Render analysis result
        renderResults(data);

    } catch (err) {
        console.error("Analysis Request Error:", err);
        showError("Unable to connect to the backend server. Please verify Flask is running.");
    } finally {
        setLoading(false);
    }
}

/**
 * Render the verdict and feature breakdown in the UI
 */
function renderResults(data) {
    const resultSection = document.getElementById("resultSection");
    const verdictCard = document.getElementById("verdictCard");
    const verdictTitle = document.getElementById("verdictText");
    const verdictIcon = document.getElementById("verdictIcon");
    const confidenceVal = document.getElementById("confidenceValue");
    const confidenceBar = document.getElementById("confidenceBar");
    const scannedUrlText = document.getElementById("scannedUrlText");
    const riskBadge = document.getElementById("riskLevelBadge");
    const featureGrid = document.getElementById("featureGrid");

    const isPhishing = data.prediction === 1;

    // Reset previous classes
    verdictCard.classList.remove("legitimate", "phishing");

    if (isPhishing) {
        verdictCard.classList.add("phishing");
        verdictTitle.textContent = "Phishing Website Detected";
        verdictIcon.innerHTML = '<i class="fa-solid fa-triangle-exclamation"></i>';
        riskBadge.className = "badge badge-high-risk";
        riskBadge.innerHTML = '<i class="fa-solid fa-radiation"></i> High Threat Risk';
    } else {
        verdictCard.classList.add("legitimate");
        verdictTitle.textContent = "Legitimate Website";
        verdictIcon.innerHTML = '<i class="fa-solid fa-shield-check"></i>';
        riskBadge.className = "badge badge-low-risk";
        riskBadge.innerHTML = '<i class="fa-solid fa-circle-check"></i> Safe / Low Risk';
    }

    // Confidence & URL
    const confPercent = Math.round(data.confidence * 100);
    confidenceVal.textContent = `${confPercent}%`;
    confidenceBar.style.width = `${confPercent}%`;
    scannedUrlText.textContent = data.url;

    // Render Features Grid
    featureGrid.innerHTML = "";
    if (data.display_features && Array.isArray(data.display_features)) {
        data.display_features.forEach(feat => {
            const card = document.createElement("div");
            card.className = `feature-card ${feat.is_risk ? 'risk' : 'safe'}`;

            const badgeClass = feat.is_risk ? 'feat-status-risk' : 'feat-status-safe';
            const statusIcon = feat.is_risk ? '<i class="fa-solid fa-triangle-exclamation"></i>' : '<i class="fa-solid fa-check"></i>';

            card.innerHTML = `
                <div>
                    <div class="feat-top">
                        <span class="feat-name">${escapeHtml(feat.name)}</span>
                        <span class="feat-status-badge ${badgeClass}">${statusIcon} ${escapeHtml(feat.status)}</span>
                    </div>
                    <div class="feat-value">${escapeHtml(feat.value)}</div>
                </div>
                <div class="feat-desc">${escapeHtml(feat.description)}</div>
            `;
            featureGrid.appendChild(card);
        });
    }

    // Display result section smoothly
    resultSection.style.display = "block";
    resultSection.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

/**
 * Utility to escape HTML strings preventing injection
 */
function escapeHtml(str) {
    if (str === null || str === undefined) return "";
    return String(str)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

