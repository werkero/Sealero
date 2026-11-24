export interface PrivacyConsentStore {
  /** Records the current privacy policy acceptance, preserving the first acceptance for an existing version. */
  recordPrivacyConsent(
    userId: string,
    policyVersion: string,
    ipAddress: string | null,
    consentedAt: Date,
  ): Promise<string>;
}
