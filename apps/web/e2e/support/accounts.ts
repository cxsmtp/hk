/**
 * The first administrator of the browser tests' throwaway installation: playwright.config.ts hands these to the API
 * (FIRST_RUN_ACCESS with ADMIN_EMAIL and ADMIN_PASSWORD), and the first-run test replaces the temporary password with
 * `password`. Synthetic values for a disposable test database only.
 */
export const ADMIN = {
  email: "admin@hawk-e2e.test",
  temporaryPassword: "Temporary-Admin-2026",
  password: "Chosen-Admin-Pass-2026",
  organisation: "E2E Organisation",
};
