namespace GuardianAngel.App.Content;

public sealed record LearnTopic(string Title, string Body);

/// <summary>The first-launch guide and the Learn tab. Plain language, no jargon.</summary>
public static class LearnContent
{
    public static readonly IReadOnlyList<LearnTopic> Topics =
    [
        new("What Guardian Angel does",
            "Guardian Angel doesn't filter the internet by itself. You choose a filter (like CleanBrowsing, Cloudflare for Families, NextDNS, or your own server). " +
            "Guardian Angel locks your PC to that filter and closes the usual ways around it.\n\n" +
            "It works on this PC only. Other devices (your phone, a console, another computer) need their own protection."),
        new("Tightening is instant, loosening waits",
            "Anything that makes your protection stronger happens right away. Right now that's making your wait time longer.\n\n" +
            "Anything that makes it weaker has to wait out the delay you chose: changing your filter, a shorter delay, removing your partner, or uninstalling."),
        new("Delays",
            "When you ask to loosen something, a countdown starts. Changing the clock doesn't speed it up, and it keeps counting after a restart. " +
            "Time with the PC switched off counts only when Guardian Angel can check the real time on the internet afterwards.\n\n" +
            "Pick a delay longer than a weak moment lasts. Many people choose 12 to 24 hours."),
        new("Queued changes",
            "You choose the exact change when you ask for it. When the delay ends, Guardian Angel applies it automatically, even if you're not at the PC. Only that change happens.\n\n" +
            "You can see every pending change with its countdown, and cancel any of them at any time. Asking again for the same setting restarts its countdown."),
        new("Unlock windows (coming soon)",
            "Some needs are open-ended, like temporary admin rights. A later version adds unlock windows: when the delay ends you press \"Start unlock\" and get a short window.\n\n" +
            "Shorter windows protect you better. Use queued changes when you know exactly what you need."),
        new("Accountability partners",
            "A partner is someone you trust. During setup they scan a QR code with any authenticator app (Google Authenticator, Microsoft Authenticator, and so on).\n\n" +
            "Their 6-digit code can approve a pending change right away. Each code works once. Five wrong codes lock codes out for an hour. " +
            "The secret is never shown again after setup, not even to you."),
        new("The three setup paths",
            "Simple: one public filter for everything. This is the easiest, and it's ready now.\n\n" +
            "Home + on the go: your home DNS server at home, and a public filter when you're away (coming in a later version).\n\n" +
            "Own server everywhere: your own filter through Tailscale, wherever you are (coming in a later version)."),
        new("The Vault (coming soon)",
            "The Vault stores passwords you want kept from yourself: your router, your filter's dashboard, your BIOS, your phone's Screen Time code. " +
            "Seeing one is a queued change, so it waits out your delay too."),
        new("Why a standard account matters",
            "Someone with admin rights can, with enough effort, remove anything. The next version helps you move admin rights to a hidden account " +
            "whose password lives in the Vault, so your everyday account is a standard one. Until then, Guardian Angel slows you down, but an admin can still get around it."),
        new("Honest limits",
            "No software can stop someone who is fully determined and can open the PC. The goal is to make getting around Guardian Angel take far longer than a weak moment lasts.\n\n" +
            "It works best alongside real accountability: a partner, a community, and your own reasons for doing this."),
    ];
}
