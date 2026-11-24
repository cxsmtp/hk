import { describe, expect, it } from "vitest";

import { detectMeetingAiNotetaker, detectMeetingSurface } from "./meeting-notetaker";

describe("meeting notetaker detection", () => {
  it("detects Fireflies as a visible AI notetaker in Google Meet", () => {
    const detection = detectMeetingAiNotetaker({
      hostname: "meet.google.com",
      visibleText: "Participants John Doe Fireflies.ai Notetaker Jane Doe",
    });

    expect(detection).toMatchObject({
      surface: "google_meet",
      provider: "fireflies",
      providerLabel: "Fireflies.ai",
      participantVisible: true,
      controlMode: "external_required",
    });
  });

  it("detects Read.ai as a visible AI notetaker in Microsoft Teams", () => {
    const detection = detectMeetingAiNotetaker({
      hostname: "teams.microsoft.com",
      visibleText: "People in this call Read AI Meeting Notes Ayush Security",
    });

    expect(detection).toMatchObject({
      surface: "microsoft_teams",
      provider: "read_ai",
      providerLabel: "Read.ai",
    });
  });

  it("does not flag normal participants or business discussion as notetakers", () => {
    const detection = detectMeetingAiNotetaker({
      hostname: "meet.google.com",
      visibleText: "Participants Jane Client Corp Contract review AI transformation strategy",
    });

    expect(detection).toBeNull();
  });

  it("detects generic AI notetaker wording without trusting plain AI mentions", () => {
    expect(
      detectMeetingAiNotetaker({
        hostname: "teams.microsoft.com",
        visibleText: "Participants AI notetaker joined the meeting",
      }),
    ).toMatchObject({ provider: "generic_ai_notetaker" });

    expect(
      detectMeetingAiNotetaker({
        hostname: "teams.microsoft.com",
        visibleText: "We are discussing AI strategy and meeting notes later",
      }),
    ).toBeNull();
  });

  it("classifies meeting surfaces from browser hostnames", () => {
    expect(detectMeetingSurface("meet.google.com")).toBe("google_meet");
    expect(detectMeetingSurface("teams.microsoft.com")).toBe("microsoft_teams");
    expect(detectMeetingSurface("teams.live.com")).toBe("microsoft_teams");
    expect(detectMeetingSurface("chatgpt.com")).toBe("unknown");
  });
});
