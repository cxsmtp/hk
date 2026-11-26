"""Curated, versioned prompt-injection and jailbreak rule set.

Rules run on the normalised views of a text (plain, de-leeted, de-spaced, and decoded base64/hex/percent segments),
so "1gn0re previous instructions", "i g n o r e ...", Cyrillic look-alikes and a base64 blob all reach the same rule.
Each rule has a stable id (reason code ``pi.rule.<id>``), a category (``pi.category.<category>``) and a weight; the
engine combines weights with the statistical classifier (injection_engine.py).

Bump RULESET_VERSION whenever a rule is added, removed or its meaning changes; ids are never reused.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, replace

RULESET_VERSION = "2026.11.1"

CATEGORIES = (
    "instruction_override",
    "roleplay_jailbreak",
    "system_prompt_extraction",
    "tool_abuse",
    "indirect_injection",
    "encoded_payload",
    "policy_evasion",
    "data_exfiltration",
)


@dataclass(frozen=True)
class Rule:
    id: str
    category: str
    weight: float
    pattern: re.Pattern[str]
    scope: str = "any"  # any | direct (the user's own prompt) | indirect (retrieved content, tool output)
    language: str = "en"
    unless: re.Pattern[str] | None = None  # a match that also matches this is not counted (benign look-alikes)
    anchors: tuple[str, ...] = ()  # substrings one of which every match contains (a fast prefilter; empty: always run)


# Shared vocabulary. Inputs are already case-folded and whitespace-collapsed.
_IGNORE = r"(?:ignore|ignoring|disregard|disregarding|forget|forgetting|skip|neglect|discard|drop|abandon|override|overrule|bypass|throw\s+out|set\s+aside|pay\s+no\s+attention\s+to|do\s+not\s+(?:follow|obey|listen\s+to)|don'?t\s+(?:follow|obey|listen\s+to)|stop\s+(?:following|obeying))"
_PRIOR = r"(?:previous|prior|above|earlier|preceding|foregoing|former|initial|original|old|existing|default|given|system|developer|all|any|every|the|your|these|those|its|my|of\s+your|everything)"
_RULES_N = r"(?:instructions?|directions?|directives?|prompts?|rules?|guidelines?|guardrails?|constraints?|restrictions?|polic(?:y|ies)|context|programming|training|safeguards?|filters?|system\s+(?:prompt|message)s?|guidance|limitations?)"
_FILL = r"(?:\s+[\w'’-]+){0,4}?"
_YOU = r"(?:you|u|ya|the\s+(?:ai|assistant|model|bot)|chatgpt|claude|gemini|copilot|llm)"
_SYSPROMPT = r"(?:system\s*prompt|system\s+message|initial\s+(?:prompt|instructions?)|original\s+(?:prompt|instructions?)|hidden\s+(?:prompt|instructions?|rules?)|secret\s+(?:prompt|instructions?)|pre-?prompt|meta-?prompt|developer\s+(?:message|prompt|instructions?)|internal\s+(?:instructions?|rules?|guidelines?)|(?:instructions|text|prompt|rules|context)\s+you\s+(?:were|have\s+been)\s+(?:given|initiali[sz]ed\s+with|configured\s+with|primed\s+with|started\s+with|set\s+up\s+with)|(?:instructions|text|prompt|rules)\s+you\s+(?:got|received|were\s+sent)\b|(?:hidden|initial|original|secret|internal)\s+(?:setup|configuration|config|context|preamble)(?:\s+text)?|your\s+(?:instructions|rules|guidelines|configuration|prompt|setup\s+text)|the\s+(?:instructions|rules|guidelines)\s+(?:you\s+(?:follow|were\s+given|obey)|that\s+govern\s+you))"
_REVEAL = r"(?:reveal|show|print|display|output|repeat|recite|dump|leak|expose|disclose|share|tell\s+me|give\s+me|write\s+out|spell\s+out|echo|list|paste|copy|return|translate)"


def _r(pattern: str) -> re.Pattern[str]:
    # The views matched are already case-folded, so no IGNORECASE (it makes Python's matcher about three times slower).
    return re.compile(pattern, re.DOTALL)


RULES: tuple[Rule, ...] = (
    # --- Instruction override -------------------------------------------------------------------------------------
    Rule("override_ignore_prior", "instruction_override", 0.9, _r(rf"\b{_IGNORE}\b{_FILL}\s+{_PRIOR}\b{_FILL}\s+{_RULES_N}\b")),
    Rule("override_ignore_short", "instruction_override", 0.75, _r(rf"\b(?:ignore|disregard|forget)\s+(?:all|everything|anything)\s+(?:(?:you\s+(?:were|have\s+been)\s+)?(?:told|said|instructed|taught)|before|above|prior)\b|\b(?:ignore|disregard|forget)\s+(?:what|whatever|anything|everything)\s+(?:the\s+|your\s+)?(?:developers?|system|operators?|admins?|administrators?|creators?|openai|anthropic|they|you\s+were|you've\s+been)\s+(?:told|said|instructed|wrote|programmed|have\s+told|has\s+told)")),
    Rule("override_new_instructions", "instruction_override", 0.7, _r(r"(?:^|[\n.!:>\]])\s*(?:#+\s*)?(?:(?:new|updated|revised|real|actual|true|override|important|urgent|admin|priority)\s+(?:system\s+)?(?:instructions?|directives?|rules?|orders?|task|prompt)|(?:system|admin|administrator|developer|root|security)\s+(?:override|command|directive))\s*[:\-=]")),
    Rule("override_from_now_on", "instruction_override", 0.6, _r(rf"\b(?:from\s+now\s+on|for\s+the\s+rest\s+of\s+(?:this|the)\s+conversation|henceforth|starting\s+now)\b[,\s]+{_YOU}?\s*(?:will|must|shall|are\s+to|should|have\s+to)\s+(?:ignore|disregard|answer\s+without|respond\s+without|no\s+longer|never\s+refuse|always\s+(?:comply|answer|obey))")),
    Rule("override_instead_follow", "instruction_override", 0.65, _r(r"\b(?:instead|rather)\b[,\s]+(?:follow|obey|execute|do|carry\s+out)\s+(?:these|my|the\s+following|only\s+my)\s+(?:new\s+)?(?:instructions?|commands?|orders?|directions?)")),
    Rule("override_no_longer_bound", "instruction_override", 0.75, _r(rf"\b{_YOU}\s+(?:are|re|'re)\s+(?:no\s+longer|not)\s+(?:bound|restricted|limited|constrained)\s+by\b")),
    Rule("override_rules_dont_apply", "instruction_override", 0.75, _r(rf"\b(?:your|the|those|these|all)\s+{_RULES_N}\s+(?:do\s+not|don'?t|no\s+longer)\s+apply\b")),
    Rule("override_priority_claim", "instruction_override", 0.65, _r(r"\b(?:this|the\s+following|these)\s+(?:instructions?|message|text|prompt)\s+(?:override|overrides|supersede|supersedes|take[s]?\s+precedence\s+over|replace[s]?)\s+(?:all|any|every|your|the)\b")),
    Rule("override_reset_context", "instruction_override", 0.6, _r(r"\b(?:reset|clear|wipe|erase|flush)\s+(?:your|the|all)\s+(?:context|memory|instructions|rules|conversation\s+history|previous\s+instructions)\b")),
    # --- Role play / persona / DAN ---------------------------------------------------------------------------------
    Rule("jailbreak_dan", "roleplay_jailbreak", 0.9, _r(r"\b(?:dan\s+mode|do\s+anything\s+now|\bdan\b\s*(?:prompt|jailbreak|\d+(?:\.\d+)?)|you\s+are\s+(?:now\s+)?dan\b|act\s+as\s+dan\b|stan\s+mode|dude\s+mode|aim\s+mode|evil\s*bot|anti-?dan|jailbroken|jailbreak(?:ed)?\s+mode)")),
    Rule("jailbreak_unrestricted_persona", "roleplay_jailbreak", 0.85, _r(rf"\b(?:you\s+are\s+(?:now\s+)?|act(?:ing)?\s+as\s+|pretend\s+(?:to\s+be|you\s+are)\s+|roleplay\s+as\s+|role-play\s+as\s+|become\s+|simulate\s+|behave\s+like\s+|respond\s+as\s+)(?:an?\s+)?(?:\w+\s+){{0,2}}?(?:unrestricted|unfiltered|uncensored|amoral|unethical|unaligned|unbound|unlimited|lawless|rogue|evil|jailbroken|uncontrolled|no-?limits?|without\s+(?:any\s+)?(?:restrictions|filters|rules|limits|guidelines|ethics|morals)|(?:\w+[\s,]+){{0,3}}?(?:with\s+)?(?:zero|no)\s+(?:limitations|limits|restrictions|rules|filters|guidelines|boundaries|censorship|ethics))\b")),
    Rule("jailbreak_mode_switch", "roleplay_jailbreak", 0.8, _r(r"\b(?:enable|activate|enter|switch\s+(?:in)?to|turn\s+on|unlock|engage)\s+(?:the\s+)?(?:developer|dev|god|admin|root|debug|sudo|unrestricted|unfiltered|uncensored|jailbreak|maintenance|override|test)\s+mode\b"), unless=_r(r"\b(?:my\s+own|on\s+(?:my|the|an?|your)\s+(?:\w+\s+)?(?:router|nas|phone|device|laptop|android|iphone|ipad|chromebook|pc|mac|tv|console|car|browser|app)|settings|bios|firmware)\b")),
    Rule("jailbreak_no_rules_hypothetical", "roleplay_jailbreak", 0.75, _r(rf"\b(?:pretend|imagine|suppose|assume|hypothetically|in\s+a\s+(?:fictional|hypothetical)\s+world)\b{_FILL}\s+(?:you\s+(?:have|had)\s+no|there\s+(?:are|were)\s+no|without\s+any|free\s+(?:of|from)\s+(?:all\s+)?(?:your\s+)?)\s*(?:\w+\s+){{0,2}}?(?:rules|restrictions|filters|guidelines|limits|limitations|ethic(?:s|al\s+guidelines)|moral(?:s|ity)|safety\s+(?:rules|guidelines|filters)|content\s+polic(?:y|ies)|programming)\b")),
    Rule("jailbreak_safety_off", "roleplay_jailbreak", 0.8, _r(r"\b(?:safety|content\s+filter|filters?|guardrails?|moderation|censorship|ethical\s+guidelines|alignment|(?:compliance|security|safety|policy|content)\s+(?:checks?|controls?|rules|layers?)|safeguards|protections|restrictions)\s+(?:is|are|has\s+been|have\s+been|now|=)\s*(?:off|disabled|removed|turned\s+off|deactivated|false|0|bypassed|suspended)\b|\b(?:disable|turn\s+off|deactivate|remove|bypass|suspend)\s+(?:your\s+|all\s+|the\s+)?(?:safety|content\s+filters?|filters|guardrails|moderation|censorship|ethical\s+guidelines|alignment)\b")),
    Rule("jailbreak_never_refuse", "roleplay_jailbreak", 0.7, _r(rf"\b{_YOU}?\s*(?:will|must|should|shall|can)\s+(?:never|not)\s+(?:refuse|decline|say\s+no|warn|add\s+(?:any\s+)?disclaimers?|mention\s+(?:ethics|safety|legality)|break\s+character)\b|\bwithout\s+(?:any\s+)?(?:refusals?|warnings?|disclaimers?|moralizing|censorship)\b")),
    Rule("jailbreak_dual_response", "roleplay_jailbreak", 0.75, _r(r"\b(?:two|2|dual|both)\s+(?:responses|answers|replies)\b.{0,80}\b(?:normal|classic|standard|filtered)\b.{0,80}\b(?:jailbroken|unfiltered|dan|developer\s+mode|unrestricted)\b|\[(?:🔓|jailbreak|dan|unlocked)\]")),
    Rule("jailbreak_grandma", "roleplay_jailbreak", 0.6, _r(r"\b(?:my\s+)?(?:deceased|late|dead)\s+(?:grandma|grandmother|grandpa|grandfather)\b.{0,120}\b(?:used\s+to|would)\s+(?:tell|read|recite|give)\b")),
    Rule("jailbreak_token_game", "roleplay_jailbreak", 0.6, _r(r"\byou\s+(?:have|start\s+with)\s+\d+\s+tokens\b.{0,120}\b(?:lose|deduct|die|cease\s+to\s+exist)\b")),
    # --- System prompt extraction -------------------------------------------------------------------------------------
    Rule("extract_system_prompt", "system_prompt_extraction", 0.85, _r(rf"\b{_REVEAL}\b{_FILL}\s+{_SYSPROMPT}\b"), unless=_r(r"\b(?:our|my|their|template|sample|example|draft)\b")),
    Rule("extract_what_instructions", "system_prompt_extraction", 0.7, _r(r"\bwhat\s+(?:are|were|is)\s+(?:your\s+(?:exact\s+|original\s+|initial\s+|hidden\s+|secret\s+|full\s+)?|the\s+(?:exact\s+|original\s+|initial\s+|hidden\s+|secret\s+|full\s+))(?:instructions|system\s*prompt|system\s+message|initial\s+prompt|rules\s+you\s+(?:were|have\s+been)\s+given|guidelines\s+you\s+follow)\b|\bwhat\s+(?:is|was)\s+the\s+system\s*(?:prompt|message)\s+(?:you|that\s+you)\s+(?:were|are|have|got)\b")),
    Rule("extract_repeat_above", "system_prompt_extraction", 0.8, _r(r"\b(?:repeat|print|output|copy|recite|reproduce)\s+(?:back\s+)?(?:everything|all(?:\s+(?:of\s+)?the\s+(?:text|words|content|messages?|lines?))?|the\s+(?:text|words|content|messages?|lines?))\s+(?:above|before\s+this|preceding|prior\s+to\s+this|from\s+the\s+(?:start|beginning))\b|\beverything\s+(?:above|before)\s+this\s+(?:line|message|point)\b|\bstart(?:ing)?\s+(?:your\s+(?:answer|response|reply)\s+)?with\s+[\"']?you\s+are\s+(?:a|an|chatgpt)\b")),
    Rule("extract_verbatim", "system_prompt_extraction", 0.6, _r(rf"\b(?:verbatim|word\s+for\s+word|in\s+full|unredacted|in\s+a\s+code\s+block)\b.{{0,60}}\b{_SYSPROMPT}\b|\b{_SYSPROMPT}\b.{{0,60}}\b(?:verbatim|word\s+for\s+word|in\s+full|unredacted)\b")),
    # --- Tool / function abuse ---------------------------------------------------------------------------------------------
    Rule("tool_forced_call", "tool_abuse", 0.65, _r(r"\b(?:call|invoke|run|execute|use|trigger)\s+(?:the\s+)?(?:\w+\s+)?(?:tool|function|plugin|action|api|command)\b.{0,60}\b(?:without|no)\s+(?:asking|confirmation|approval|permission|telling|checking|notifying)\b")),
    Rule("tool_shell_payload", "tool_abuse", 0.8, _r(r"\b(?:curl|wget|invoke-webrequest|iwr)\b[^\n]{0,120}\|\s*(?:bash|sh|zsh|powershell|iex|python)\b|\brm\s+-rf\s+(?:/|~|\*|\$home)|\b(?:nc|ncat|netcat)\s+-e\b|\bbash\s+-i\s+>&\s*/dev/tcp/|powershell\s+(?:-enc|-encodedcommand)\b|\bchmod\s+\+x\b.{0,40}&&")),
    Rule("tool_privileged_action", "tool_abuse", 0.6, _r(r"\b(?:grant|give|assign|add)\s+(?:me|this\s+user|the\s+attacker|user\s+\S+)\s+(?:admin|administrator|root|owner|superuser|full)\s*(?:access|rights|role|privileges?|permissions?)?\b|\b(?:delete|drop|wipe|truncate|destroy)\s+(?:all|every|the\s+entire|the\s+whole)\s+(?:files?|records?|tables?|databases?|users?|repositor(?:y|ies)|backups?)\b")),
    Rule("tool_fake_result", "tool_abuse", 0.7, _r(r"<\s*/?\s*(?:tool_result|function_results?|function_call|tool_call|tool_use)\s*>|\"(?:role|name)\"\s*:\s*\"(?:system|tool|function)\"\s*,\s*\"content\"\s*:")),
    # --- Indirect injection in retrieved / tool content ----------------------------------------------------------------------
    Rule("indirect_ai_addressed", "indirect_injection", 0.75, _r(rf"\b(?:note|attention|message|instructions?|important|notice)\s+(?:to|for)\s+(?:the\s+)?(?:ai|assistant|chatbot|language\s+model|llm|agent|bot|gpt|claude|copilot|model)\b|\b(?:if|when)\s+(?:you\s+are\s+)?(?:an?\s+)?(?:ai|assistant|language\s+model|llm|agent|chatbot)\s+(?:reading|processing|summari[sz]ing|parsing)\s+(?:this|these)\b|\bai\s+(?:assistants?|agents?|models?)\s+(?:reading|processing|summari[sz]ing)\s+this\b|\bas\s+(?:the|an?)\s+(?:ai|assistant|llm|language\s+model|agent|chatbot|model)\s+(?:reading|processing|summari[sz]ing|browsing|parsing)\s+(?:this|these)\b")),
    Rule("indirect_hidden_markup", "indirect_injection", 0.7, _r(r"<!--\s*(?:ai|assistant|system|prompt|instruction|llm|agent)\b.*?-->|\[\s*(?:hidden|secret|system)\s+(?:instruction|prompt|message)s?\s*\]|\{\{\s*system\s*\}\}|<\s*(?:system|im_start|im_end|\|im_start\||\|im_end\||\|system\||\|endoftext\|)\s*>|\[/?inst\]|<<\s*/?sys\s*>>|(?:^|\n)\s*#{2,3}\s*(?:system|instruction)\s*:?\s*\n")),
    Rule("indirect_ignore_user", "indirect_injection", 0.75, _r(r"\b(?:ignore|disregard)\s+(?:the\s+)?user'?s?\s+(?:question|query|request|instructions?|message)\b|\b(?:do\s+not|don'?t)\s+(?:tell|inform|alert|mention\s+(?:this\s+)?to)\s+the\s+user\b|\bwithout\s+(?:the\s+user|them)\s+(?:knowing|noticing)\b")),
    Rule("indirect_authority_spoof", "indirect_injection", 0.55, _r(r"\b(?:this\s+(?:document|page|email|file|content|context|source)\s+(?:is\s+authoritative|overrides|supersedes|must\s+be\s+followed|contains\s+(?:new|updated)\s+instructions))\b|\b(?:message|instruction)s?\s+from\s+(?:the\s+)?(?:system|developer|administrator|openai|anthropic|security\s+team)\s*:")),
    Rule("indirect_response_steering", "indirect_injection", 0.55, _r(r"\b(?:when|if|whenever)\s+(?:the\s+user\s+|a\s+user\s+|users\s+|someone\s+|anyone\s+)?(?:asked|asks?|queried|queries|requests?|summari[sz]\w*|answering)\b.{0,80}\b(?:always|you\s+must|only|instead)\s+(?:say|respond|answer|reply|recommend|state|include|send|link|tell)\b")),
    # --- Encoded payloads ---------------------------------------------------------------------------------------------------
    Rule("encoded_decode_and_follow", "encoded_payload", 0.75, _r(r"\b(?:decode|decrypt|deobfuscate|translate|convert|unscramble|reverse)\b.{0,60}\b(?:base64|b64|hex|rot-?13|binary|morse|caesar|cipher|encoded|reversed)\b.{0,80}\b(?:follow|execute|obey|run|do\s+what|carry\s+out|act\s+on|then\s+(?:answer|respond|do))\b")),
    Rule("encoded_respond_in_cipher", "encoded_payload", 0.55, _r(r"\b(?:respond|reply|answer|write)\s+(?:only\s+)?in\s+(?:base64|hex|rot-?13|binary|morse|leetspeak|reversed\s+text|caesar\s+cipher)\b.{0,80}\b(?:avoid|bypass|evade|so\s+(?:that\s+)?(?:the\s+)?(?:filter|moderation|monitor|guard))")),
    # --- Policy evasion / payload splitting ----------------------------------------------------------------------------------
    Rule("evasion_split_payload", "policy_evasion", 0.7, _r(r"\b(?:decompose|break(?:\s+down)?|split|chunk|divide)\b.{0,80}\b(?:prompt|request|payload|instructions?|question)\b.{0,80}\b(?:into|as)\b.{0,40}\b(?:steps?|parts?|chunks?|pieces?)\b.{0,80}\b(?:avoid|bypass|evade|so\s+(?:it|the\s+filter)|not\s+(?:trigger|detected|flagged))|\b(?:step[\s-]?by[\s-]?step|one\s+step\s+at\s+a\s+time|piece\s+by\s+piece)\b.{0,120}\b(?:bypass|evade|avoid|circumvent|sidestep)\b.{0,48}\b(?:policy|guard(?:rail)?s?|filter|detection|safety|moderation)\b")),
    Rule("evasion_bypass_controls", "policy_evasion", 0.7, _r(r"\b(?:bypass(?:ing)?|circumvent(?:ing)?|evad(?:e|ing)|get(?:ting)?\s+around|sidestep(?:ping)?|defeat(?:ing)?|trick(?:ing)?)\s+(?:the\s+|your\s+|any\s+|all\s+)?(?:content\s+)?(?:polic(?:y|ies)|filters?|guardrails?|safety\s+(?:measures|checks|filters|systems)|moderation|restrictions|dlp|security\s+controls|detection)\b")),
    Rule("evasion_payload_assembly", "policy_evasion", 0.6, _r(r"\b(?:let|set)\s+[a-z]\s*=\s*['\"][^'\"]{1,40}['\"]\s*[;,]?\s*(?:and\s+)?(?:let|set)?\s*[a-z]\s*=\s*['\"][^'\"]{1,40}['\"].{0,80}\b(?:concatenat|combine|join|a\s*\+\s*b)")),
    # --- Data exfiltration through the model ---------------------------------------------------------------------------------
    Rule("exfil_send_elsewhere", "data_exfiltration", 0.75, _r(r"\b(?:send|post|upload|forward|transmit|exfiltrate|leak|email|beacon)\b.{0,60}\b(?:conversation|chat\s+history|system\s+prompt|secrets?|api\s+keys?|credentials|passwords?|tokens?|the\s+(?:data|context|document)|user\s+data)\b.{0,60}\b(?:to|at|via)\s+(?:https?://|http://|\S+@\S+\.\w+|my\s+(?:server|webhook|endpoint)|an?\s+(?:external|remote)\s+(?:server|url|endpoint))")),
    Rule("exfil_markdown_image", "data_exfiltration", 0.8, _r(r"!\[[^\]]{0,40}\]\(\s*https?://[^\s)]{1,200}[?&][\w-]{1,20}=\s*(?:\{|\$|<|%7b|\[)")),
    # --- Multi-language instruction override and extraction ---------------------------------------------------------------
    Rule("ml_override_fr", "instruction_override", 0.85, _r(r"\b(?:ignore[zr]?|oublie[zr]?|ne\s+tiens\s+pas\s+compte\s+d)\s*(?:toutes\s+|tous\s+)?(?:les|des|tes|vos)\s+(?:\w+\s+)?(?:instructions|consignes|r[eè]gles|directives)\s*(?:pr[eé]c[eé]dentes|ant[eé]rieures|initiales|ci-dessus)?"), language="fr"),
    Rule("ml_override_es", "instruction_override", 0.85, _r(r"\b(?:ignora|ignore|olvida|olvide|omite|descarta)\s+(?:todas\s+)?(?:las|tus|sus)\s+(?:\w+\s+)?(?:instrucciones|reglas|indicaciones|directrices)\s*(?:anteriores|previas|iniciales)?"), language="es"),
    Rule("ml_override_pt", "instruction_override", 0.85, _r(r"\b(?:ignore|ignora|esque[cç]a|desconsidere)\s+(?:todas\s+)?(?:as|suas|tuas)\s+(?:\w+\s+)?(?:instru[cç][oõ]es|regras|diretrizes)\s*(?:anteriores|pr[eé]vias|iniciais)?"), language="pt"),
    Rule("ml_override_it", "instruction_override", 0.85, _r(r"\b(?:ignora|dimentica|trascura)\s+(?:tutte\s+)?(?:le|tue)\s+(?:\w+\s+)?(?:istruzioni|regole|direttive)\s*(?:precedenti|iniziali)?"), language="it"),
    Rule("ml_override_de", "instruction_override", 0.85, _r(r"\b(?:ignoriere|ignorier|vergiss|vergessen\s+sie|missachte|ignorieren\s+sie)\s+(?:(?:alle\s+|die\s+|deine\s+|ihre\s+)?(?:\w+\s+)?(?:vorherigen|bisherigen|obigen|vorigen|urspr[uü]nglichen)?\s*(?:anweisungen|instruktionen|regeln|vorgaben|richtlinien)|alles\b[^.!?\n]{0,40}\b(?:gesagt|vorher|bisher|zuvor))"), language="de"),
    Rule("ml_override_nl", "instruction_override", 0.85, _r(r"\b(?:negeer|vergeet)\s+(?:alle\s+)?(?:de\s+|je\s+)?(?:vorige|eerdere|vorige)?\s*(?:instructies|regels|richtlijnen)"), language="nl"),
    Rule("ml_override_tr", "instruction_override", 0.85, _r(r"\b(?:önceki|tüm|bütün)\s+(?:talimatlar[ıi]|kurallar[ıi])\s+(?:yok\s+say|görmezden\s+gel|unut)"), language="tr"),
    Rule("ml_override_ru", "instruction_override", 0.85, _r(r"(?:игнорируй|игнорируйте|забудь|забудьте|проигнорируй|не\s+обращай\s+внимания\s+на)\s+(?:все\s+)?(?:предыдущие|прежние|старые|свои|твои|данные\s+ранее)?\s*(?:инструкции|указания|правила|команды)"), language="ru"),
    Rule("ml_override_ar", "instruction_override", 0.85, _r(r"(?:تجاهل|انس|إنس|اترك)\s+(?:جميع\s+|كل\s+)?(?:التعليمات|الأوامر|القواعد|التوجيهات)\s*(?:السابقة)?"), language="ar"),
    Rule("ml_override_zh", "instruction_override", 0.85, _r(r"(?:忽略|无视|忘记|忘掉|不要理会|忽视)\s*(?:你的?|您的?)?\s*(?:之前|以上|上面|先前|所有|全部|以前)?\s*(?:的)?\s*(?:所有|全部)?\s*(?:指令|指示|说明|规则|提示|要求|限制)"), language="zh"),
    Rule("ml_override_ja", "instruction_override", 0.85, _r(r"(?:以前|前|上記|これまで)の(?:指示|命令|ルール|指令)を(?:無視|忘れ)"), language="ja"),
    Rule("ml_override_hi", "instruction_override", 0.85, _r(r"(?:पिछले|पहले\s+के|सभी)\s+(?:निर्देशों|निर्देश|नियमों)\s+(?:को\s+)?(?:अनदेखा|नज़रअंदाज़|भूल)"), language="hi"),
    Rule("ml_extract_fr", "system_prompt_extraction", 0.8, _r(r"\b(?:r[eé]v[eè]le|montre|affiche|donne[- ]moi|r[eé]p[eè]te)\w*\s+(?:ton|votre|le)\s+(?:prompt|message)\s+(?:syst[eè]me|initial)"), language="fr"),
    Rule("ml_extract_es", "system_prompt_extraction", 0.8, _r(r"\b(?:revela|muestra|mu[eé]strame|dime|repite|imprime)\s+(?:tu|el|su)\s+(?:prompt|mensaje|instrucciones?)\s+(?:del\s+sistema|de\s+sistema|inicial(?:es)?|ocultas?)"), language="es"),
    Rule("ml_extract_de", "system_prompt_extraction", 0.8, _r(r"\b(?:zeige?|verrate|gib|wiederhole|nenne)\s+(?:mir\s+)?(?:deinen|ihren|den)\s+(?:system-?prompt|systemnachricht|anfangs-?prompt|versteckten\s+anweisungen)"), language="de"),
    Rule("ml_extract_zh", "system_prompt_extraction", 0.8, _r(r"(?:显示|告诉我|输出|透露|重复|打印)\s*(?:你的)?\s*(?:系统提示|系统消息|初始指令|隐藏指令)"), language="zh"),
    Rule("ml_extract_ru", "system_prompt_extraction", 0.8, _r(r"(?:покажи|выведи|раскрой|повтори|напиши)\s+(?:свой|твой|мне\s+свой)?\s*(?:системный\s+(?:промпт|запрос)|системное\s+сообщение|исходные\s+инструкции)"), language="ru"),
    Rule("ml_extract_ar", "system_prompt_extraction", 0.8, _r(r"(?:اكشف|أظهر|اعرض|كرر)\s+(?:لي\s+)?(?:موجه\s+النظام|تعليمات\s+النظام|التعليمات\s+المخفية)"), language="ar"),
    Rule("ml_jailbreak_es_fr_de", "roleplay_jailbreak", 0.75, _r(r"\b(?:sin\s+(?:ninguna\s+)?(?:restricciones|filtros|censura)|sans\s+(?:aucune\s+)?(?:restriction|filtre|censure)s?|ohne\s+(?:jegliche\s+)?(?:einschr[aä]nkungen|filter|zensur))\b.{0,60}\b(?:modo|mode|modus|responde|r[eé]ponds|antworte|act[uú]a|agis|handle)\b|\b(?:modo|mode|modus)\s+(?:desarrollador|d[eé]veloppeur|entwickler)\b"), language="multi"),
)

# Cheap prefilter: a rule runs only on a view that contains one of its anchor substrings (every match of the rule
# contains one). Python's matcher tries a pattern at every position of a 4 KB prompt; a substring test is far cheaper.
_ANCHORS: dict[str, tuple[str, ...]] = {
    "override_ignore_prior": ("ignor", "disregard", "forget", "skip", "neglect", "discard", "drop", "abandon", "overrid", "overrul", "bypass", "throw", "aside", "pay no", "follow", "obey", "listen"),
    "override_ignore_short": ("ignor", "disregard", "forget"),
    "override_new_instructions": ("instruction", "directive", "rule", "order", "task", "prompt", "override", "command"),
    "override_from_now_on": ("from now on", "rest of", "henceforth", "starting now"),
    "override_instead_follow": ("instead", "rather"),
    "override_no_longer_bound": ("bound", "restricted", "limited", "constrained"),
    "override_rules_dont_apply": ("apply",),
    "override_priority_claim": ("overrid", "supersede", "precedence", "replace"),
    "override_reset_context": ("reset", "clear", "wipe", "erase", "flush"),
    "jailbreak_dan": ("dan", "do anything", "stan", "dude", "aim mode", "evil", "jailbr"),
    "jailbreak_unrestricted_persona": ("you are", "act", "pretend", "roleplay", "role-play", "become", "simulat", "behave", "respond as"),
    "jailbreak_mode_switch": ("mode",),
    "jailbreak_no_rules_hypothetical": ("pretend", "imagin", "suppose", "assum", "hypothetical", "fictional"),
    "jailbreak_safety_off": ("safety", "filter", "guardrail", "moderation", "censor", "ethic", "alignment", "check", "control", "safeguard", "protection", "restriction", "rules", "layer"),
    "jailbreak_never_refuse": ("refus", "declin", "say no", "warn", "disclaimer", "ethic", "safety", "legal", "character", "moraliz", "censor"),
    "jailbreak_dual_response": ("respons", "answer", "repl", "[", "\U0001f513"),
    "jailbreak_grandma": ("grand",),
    "jailbreak_token_game": ("token",),
    "extract_system_prompt": ("reveal", "show", "print", "display", "output", "repeat", "recite", "dump", "leak", "expose", "disclose", "share", "tell me", "give me", "write out", "spell out", "echo", "list", "paste", "copy", "return", "translate"),
    "extract_what_instructions": ("what",),
    "extract_repeat_above": ("above", "before", "preceding", "prior to", "start", "beginning"),
    "extract_verbatim": ("verbatim", "word for word", "in full", "unredacted", "code block"),
    "tool_forced_call": ("asking", "confirmation", "approval", "permission", "telling", "checking", "notifying"),
    "tool_shell_payload": ("curl", "wget", "invoke-webrequest", "iwr", "rm ", "nc ", "ncat", "netcat", "/dev/tcp", "powershell", "chmod"),
    "tool_privileged_action": ("grant", "give", "assign", "add", "delete", "drop", "wipe", "truncate", "destroy"),
    "tool_fake_result": ("tool_", "function_", "\"role\"", "\"name\""),
    "indirect_ai_addressed": ("ai", "assistant", "chatbot", "model", "llm", "agent", "bot", "gpt", "claude", "copilot"),
    "indirect_hidden_markup": ("<", "[", "{{", "#"),
    "indirect_ignore_user": ("user", "without"),
    "indirect_authority_spoof": ("authoritative", "overrides", "supersedes", "must be followed", "instructions", "from"),
    "indirect_response_steering": ("always", "must", "only", "instead"),
    "encoded_decode_and_follow": ("decod", "decrypt", "deobfusc", "translat", "convert", "unscrambl", "revers"),
    "encoded_respond_in_cipher": ("base64", "hex", "rot", "binary", "morse", "leet", "reversed", "caesar"),
    "evasion_split_payload": ("decompos", "break", "split", "chunk", "divid", "step", "piece"),
    "evasion_bypass_controls": ("bypass", "circumvent", "evad", "around", "sidestep", "defeat", "trick"),
    "evasion_payload_assembly": ("let ", "set "),
    "exfil_send_elsewhere": ("send", "post", "upload", "forward", "transmit", "exfiltrat", "leak", "email", "beacon"),
    "exfil_markdown_image": ("![",),
}
RULES = tuple(replace(rule, anchors=_ANCHORS.get(rule.id, ())) for rule in RULES)

RULE_IDS: tuple[str, ...] = tuple(rule.id for rule in RULES)
if len(set(RULE_IDS)) != len(RULE_IDS):  # pragma: no cover - a programming error caught by the tests
    raise RuntimeError("prompt-injection rule ids must be unique")
