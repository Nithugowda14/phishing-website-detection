"""
Data Preprocessing Module for Phishing Website Detection System.
Handles dataset loading, validation, missing value imputation, cleaning,
and train/test splitting.
"""

import os
from typing import Tuple, Optional
import pandas as pd
from sklearn.model_selection import train_test_split

try:
    from src.feature_extraction import FEATURE_NAMES, MODEL_FEATURE_NAMES, extract_features
except ImportError:
    from feature_extraction import FEATURE_NAMES, MODEL_FEATURE_NAMES, extract_features

# Curated demonstration URLs for balanced dataset construction
DEMO_LEGIT_URLS = [
    "https://www.google.com", "https://www.youtube.com", "https://www.facebook.com",
    "https://www.wikipedia.org", "https://twitter.com", "https://www.amazon.com",
    "https://www.instagram.com", "https://www.reddit.com", "https://www.linkedin.com",
    "https://www.netflix.com", "https://www.microsoft.com", "https://www.apple.com",
    "https://www.github.com", "https://www.stackoverflow.com", "https://www.bing.com",
    "https://www.yahoo.com", "https://www.twitch.tv", "https://www.ebay.com",
    "https://www.paypal.com", "https://www.adobe.com", "https://www.cnn.com",
    "https://www.bbc.com", "https://www.nytimes.com", "https://www.theguardian.com",
    "https://www.medium.com", "https://www.quora.com", "https://www.dropbox.com",
    "https://www.spotify.com", "https://www.salesforce.com", "https://www.walmart.com",
    "https://www.target.com", "https://www.bestbuy.com", "https://www.ikea.com",
    "https://www.chase.com", "https://www.bankofamerica.com", "https://www.wellsfargo.com",
    "https://www.citigroup.com", "https://www.usps.com", "https://www.fedex.com",
    "https://www.ups.com", "https://www.dhl.com", "https://www.booking.com",
    "https://www.tripadvisor.com", "https://www.airbnb.com", "https://www.uber.com",
    "https://www.lyft.com", "https://www.slack.com", "https://www.zoom.us",
    "https://www.canva.com", "https://www.figma.com", "https://www.notion.so",
    "https://www.gitlab.com", "https://www.docker.com", "https://www.kubernetes.io",
    "https://www.python.org", "https://www.oracle.com", "https://www.ibm.com",
    "https://www.intel.com", "https://www.cisco.com", "https://www.cloudflare.com",
    "https://www.digitalocean.com", "https://www.heroku.com", "https://www.atlassian.com",
    "https://www.jira.com", "https://www.trello.com", "https://www.asana.com",
    "https://www.monday.com", "https://www.coursera.org", "https://www.edx.org",
    "https://www.udemy.com", "https://www.khanacademy.org", "https://www.codecademy.com",
    "https://www.w3schools.com", "https://developer.mozilla.org", "https://www.geeksforgeeks.org",
    "https://www.kaggle.com", "https://www.huggingface.co", "https://www.arxiv.org",
    "https://www.nature.com", "https://www.sciencedirect.com", "https://www.ieee.org",
    "https://www.acm.org", "https://www.mit.edu", "https://www.stanford.edu",
    "https://www.harvard.edu", "https://www.cam.ac.uk", "https://www.ox.ac.uk",
    "https://www.nasa.gov", "https://www.who.int", "https://www.un.org",
    "https://www.nih.gov", "https://www.cdc.gov", "https://www.weather.com",
    "https://www.imdb.com", "https://www.rottentomatoes.com", "https://www.espn.com",
    "https://www.formula1.com", "https://www.nationalgeographic.com", "https://www.forbes.com",
    "https://www.bloomberg.com"
]

DEMO_PHISH_URLS = [
    "http://192.168.1.105/login-account/verify.html", "http://203.0.113.45/paypal/update-security/",
    "http://198.51.100.22/secure/banking/signin.php", "http://104.244.42.1/chase-online-verify/login.aspx",
    "http://185.190.140.23/netflix-account-update/", "http://91.218.114.77/apple-id/confirm-billing.php",
    "http://45.142.214.12/amazon-order-support/verify/", "http://178.62.204.11/secure-bank-login/auth.html",
    "http://217.182.197.10/facebook-security-check/login", "http://149.202.160.100/microsoft-office365-verify/signin",
    "http://paypal-verification-center.security-update.com/signin/index.html",
    "http://appleid.apple.com.verify-billing-account.xyz/login.php?ref=security",
    "http://login.microsoftonline.com.secure-office365-verify.top/auth/token",
    "http://chasebank.online-secure-auth.club/customer-service/login.htm",
    "http://wellsfargo.account-protection-alert.online/banking/signin.asp",
    "http://netflix.account-billing-alert.site/your-account/update-card.php",
    "http://secure-amazon-order-delivery.support-resolve.info/verify-account",
    "http://google-drive-shared-doc-view.account-sync.net/login.jsp",
    "http://bankofamerica.online-banking-identity-verify.biz/portal/",
    "http://secure.facebook.com-login-recover.xyz/checkpoint/security-check.php",
    "http://instagram-help-copyright-infringement.support-verify.com/form",
    "http://update-secure-ebayisapi.dll-signin.info/account/confirmation",
    "http://paypal.com.webscr.cmd-login-submit.cc/myaccount/signin",
    "http://secure-wallet-connect-metamask.token-verify.io/recovery-phrase.html",
    "http://binance.com-login-authentication-code.security-alert.live/login",
    "http://usps-track-package-delivery-exception.reschedule-fee.com/pay",
    "http://dhl-express-customs-clearance-payment.tracking-update.top/billing",
    "http://fedex-redelivery-address-confirm.parcel-notice.xyz/confirm",
    "http://irs-tax-refund-status-claim.government-notice.net/deposit",
    "http://service-paypal.com-resolution-center.warning-suspend.club/signin",
    "http://security-alert.account-update.wells-fargo.banking-portal.info/",
    "http://signin.ebay.com-account-billing-dispute.suspicious-domain.cc/login",
    "http://support-dropbox-file-download.verify-credential.org/view",
    "http://steamcommunity.com-trade-offer-confirm.free-skin.ru/trade",
    "http://discord-gift-nitro-promo.free-membership.fun/claim",
    "http://secure-citi-cards.online-update-alert.biz/portal/signin",
    "http://hsbc-security-token-passcode.fraud-prevention.net/auth",
    "http://standard-chartered-online-portal.account-security.me/login",
    "http://americanexpress-online.customer-protection.co/card/verify",
    "http://whatsapp-web-qr-code-scanner.spy-account.xyz/auth",
    "http://bit.ly/3kX9q1w?login=bankofamerica", "http://tinyurl.com/secure-paypal-update-2024",
    "http://is.gd/chase_verification_alert", "http://cutt.ly/netflix-billing-issue",
    "http://t.co/apple-id-locked-recover", "http://goo.gl/verify-microsoft-security",
    "http://rebrand.ly/amazon-gift-card-claim", "http://ow.ly/facebook-account-disabled-appeal",
    "http://tiny.cc/instagram-badge-verify", "http://v.gd/citibank-urgent-pin-reset",
    "http://google.com@evil-phishing-host.com/login", "http://paypal.com@secure-verify-billing.info/signin",
    "http://microsoft.com@office365-login-verify.top/auth", "http://chase.com@192.168.1.100/account-update",
    "http://apple.com@icloud-storage-full-upgrade.biz/pay", "http://bankofamerica.com@login-portal-auth.xyz/signin",
    "http://amazon.com@prime-order-dispute.cc/refund", "http://netflix.com@stream-account-payment-fail.online/billing",
    "http://wellsfargo.com@security-code-generator.club/auth", "http://facebook.com@meta-business-suite-appeal.top/login",
    "http://legit-looking.com//phishing-redirect/login.html", "http://portal-service.net//account-verify/signin.php",
    "http://customer-support-desk.com//auth-token/verify.asp", "http://web-mail-gateway.org//owa-login/index.htm",
    "http://cloud-storage-access.info//download-secure/file.php", "http://online-banking-session.net//transfer-confirm/pin.jsp",
    "http://e-commerce-checkout.biz//card-verification/payment", "http://identity-protect.me//kyc-upload/document.html",
    "http://crypto-wallet-validator.org//restore-key/input", "http://global-security-notice.com//suspend-warning/reactivate",
    "http://apple-id-security-unlock-device-portal-auth.xyz/signin",
    "http://paypal-account-resolution-center-case-id-98124.com/verify",
    "http://microsoft-online-sharepoint-document-review-access.net/view",
    "http://chase-bank-suspicious-activity-alert-case-7489.org/login",
    "http://bankofamerica-fraud-prevention-department-hotline.biz/auth",
    "http://amazon-customer-service-order-cancellation-refund.info/claim",
    "http://netflix-membership-reactivation-billing-update-card.club/pay",
    "http://wells-fargo-commercial-banking-wire-transfer-confirm.online/portal",
    "http://google-security-team-critical-security-alert-code.top/verify",
    "http://irs-treasury-department-direct-deposit-stimulus-check.site/claim",
    "http://www.paypal-secure.com/webscr/login", "http://www.apple-id-verify.com/account/billing",
    "http://www.amazon-orders-update.com/your-account", "http://www.netflix-login-portal.com/profiles",
    "http://www.chase-secure-banking.com/online", "http://www.wellsfargo-verify-identity.com/auth",
    "http://www.bankofamerica-secure-login.com/portal", "http://www.microsoft-office365-support.com/signin",
    "http://www.google-drive-shared-doc.com/view", "http://www.facebook-appeal-center.com/disabled",
    "http://login.yahoo.mail.portal-auth.xyz/signin", "http://signin.ebay.account-recovery.top/verify",
    "http://auth.linkedin.security-update.club/confirm", "http://portal.dropbox.shared-file-download.biz/file",
    "http://secure.twitter.badge-verification.online/claim", "http://verify.instagram.copyright-strike.site/appeal",
    "http://update.whatsapp.web-session-expired.net/scan", "http://account.telegram.sms-code-verify.info/auth",
    "http://support.binance.wallet-migration.cc/connect", "http://connect.coinbase.kyc-verification.io/submit",
    "http://192.168.0.1/admin-login-router/default.asp", "http://10.0.0.1/router-firmware-update/flash.php",
    "http://172.16.0.25/firewall-credential-test/login", "http://198.18.0.12/internal-payroll-portal/auth",
    "http://203.113.88.99/university-grading-system/login", "http://118.97.234.1/government-tax-rebate/claim.html",
    "http://103.251.167.22/telecom-sim-card-kyc/update.php", "http://14.139.128.5/student-portal-fee-payment/pay.jsp",
    "http://89.248.172.16/credit-union-online-banking/auth.aspx", "http://194.87.139.77/russian-post-tracking-notice/parcel"
]


def generate_default_dataset_csv(target_path: Optional[str] = None) -> str:
    """
    Generate demonstration CSV dataset by running extract_features on curated URLs.
    """
    if target_path is None:
        base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        target_path = os.path.join(base_dir, "dataset", "phishing_dataset.csv")

    os.makedirs(os.path.dirname(target_path), exist_ok=True)

    rows = []
    # Process legitimate URLs (0)
    for u in DEMO_LEGIT_URLS:
        feats = extract_features(u)
        feats["url"] = u
        feats["label"] = 0
        rows.append(feats)

    # Process phishing URLs (1)
    for u in DEMO_PHISH_URLS:
        feats = extract_features(u)
        feats["url"] = u
        feats["label"] = 1
        rows.append(feats)

    cols = ["url"] + FEATURE_NAMES + ["label"]
    df = pd.DataFrame(rows)[cols]
    df.to_csv(target_path, index=False)
    return target_path



def load_dataset(dataset_path: str) -> pd.DataFrame:
    """
    Load the phishing dataset from CSV file.
    
    Args:
        dataset_path: Filepath to the CSV dataset.
        
    Returns:
        pd.DataFrame containing the dataset.
        
    Raises:
        FileNotFoundError: If dataset CSV does not exist.
        ValueError: If file is empty or missing target label.
    """
    if not os.path.exists(dataset_path):
        print(f"Dataset not found at '{dataset_path}'. Auto-generating demonstration dataset...")
        generate_default_dataset_csv(dataset_path)
    
    df = pd.read_csv(dataset_path)
    
    if df.empty:
        raise ValueError("Loaded dataset is empty.")
    
    if "label" not in df.columns:
        raise ValueError("Dataset must contain a 'label' column (0 for Legitimate, 1 for Phishing).")
    
    return df


def clean_and_prepare_data(df: pd.DataFrame) -> pd.DataFrame:
    """
    Clean dataset by handling nulls, verifying data types, and ensuring valid labels.
    """
    df_clean = df.copy()
    
    # Drop rows where target label is missing
    df_clean = df_clean.dropna(subset=["label"])
    
    # Ensure label is integer (0 or 1)
    df_clean["label"] = df_clean["label"].astype(int)
    
    # Check for missing feature columns and fill with 0
    for col in FEATURE_NAMES:
        if col in df_clean.columns:
            df_clean[col] = pd.to_numeric(df_clean[col], errors="coerce").fillna(0)
        else:
            # If a feature column is missing, create it with 0
            df_clean[col] = 0
            
    # Remove duplicate URL records if any
    if "url" in df_clean.columns:
        df_clean = df_clean.drop_duplicates(subset=["url"])
    else:
        df_clean = df_clean.drop_duplicates(subset=FEATURE_NAMES + ["label"])
    
    return df_clean


def get_feature_target_split(df: pd.DataFrame) -> Tuple[pd.DataFrame, pd.Series]:
    """
    Separate feature matrix X and target vector y.
    """
    df_clean = clean_and_prepare_data(df)
    X = df_clean[MODEL_FEATURE_NAMES]
    y = df_clean["label"]
    return X, y


def split_data(
    X: pd.DataFrame, 
    y: pd.Series, 
    test_size: float = 0.2, 
    random_state: int = 42
) -> Tuple[pd.DataFrame, pd.DataFrame, pd.Series, pd.Series]:
    """
    Perform stratified train-test split for balanced classification.
    """
    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=test_size,
        random_state=random_state,
        stratify=y
    )
    return X_train, X_test, y_train, y_test


def get_dataset_summary(df: pd.DataFrame) -> dict:
    """
    Generate basic statistics and class distribution for reporting.
    """
    total = len(df)
    legitimate_count = int((df["label"] == 0).sum())
    phishing_count = int((df["label"] == 1).sum())
    
    return {
        "total_samples": total,
        "legitimate_samples": legitimate_count,
        "phishing_samples": phishing_count,
        "legitimate_percentage": round((legitimate_count / total) * 100, 2) if total else 0,
        "phishing_percentage": round((phishing_count / total) * 100, 2) if total else 0,
        "feature_count": len(FEATURE_NAMES)
    }
