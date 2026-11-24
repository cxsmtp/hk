"""Browser bridge — native-messaging host relaying browser AI events to the agent.

A thin browser extension (nativeMessaging permission) sends AI-usage events to this
host over stdio; the host forwards them to the agent's control socket for an inline
decision and returns the verdict. It provides browser-native coverage only for
actions that actually traverse the managed companion; unsupported or bypassed
browser paths remain explicit gaps.
"""
