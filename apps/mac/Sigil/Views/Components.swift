//  Components.swift
//  Small shared pieces. Content sits on plain grouped surfaces; glass is reserved
//  for the control layer (see Glass.swift). These are content-layer components.

import SwiftUI

/// A one-word state pill (Armed / Pending / Approved / Denied / Expired / Locked
/// down). Color is a tint on a native capsule, never a shield or glow.
struct StatePill: View {
    let tone: StateTone
    var text: String?

    var body: some View {
        Text(text ?? tone.word)
            .font(.system(size: 11, weight: .semibold))
            .foregroundStyle(tone.color)
            .padding(.horizontal, 8)
            .padding(.vertical, 3)
            .background(tone.color.opacity(0.14), in: .capsule)
    }
}

/// A titled content section, System-Settings style: a header line and a grouped
/// card below it.
struct Section<Content: View>: View {
    let title: String
    var subtitle: String?
    @ViewBuilder var content: Content

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(.system(size: 13, weight: .semibold))
                if let subtitle {
                    Text(subtitle).font(.system(size: 11)).foregroundStyle(.secondary)
                }
            }
            content
                .padding(12)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(.background.secondary, in: .rect(cornerRadius: 12))
        }
    }
}

/// A status row: a shape-carrying glyph, a label, a value, and an optional
/// fix-it button. Used across Status and Doctor.
struct StatusRow: View {
    let ok: Bool
    var warn: Bool = false
    let label: String
    var value: String?
    var mono: Bool = false
    var fixTitle: String?
    var fix: (() -> Void)?

    private var tone: StateTone { ok ? .armed : (warn ? .warn : .denied) }

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: ok ? "checkmark.circle.fill" : (warn ? "exclamationmark.triangle.fill" : "xmark.circle.fill"))
                .foregroundStyle(tone.color)
                .font(.system(size: 13))
            Text(label).font(.system(size: 12))
            Spacer(minLength: 12)
            if let value {
                if mono { MonoText(value, size: 11, color: .secondary) }
                else { Text(value).font(.system(size: 11)).foregroundStyle(.secondary) }
            }
            if let fixTitle, let fix {
                Button(fixTitle, action: fix)
                    .buttonStyle(.glass)
                    .controlSize(.small)
            }
        }
    }
}

/// The brass gauge: a ring depleting to expiry, the brief's real clock. Collapses
/// to a numeric readout under Reduce Motion.
struct GaugeRing: View {
    let fraction: Double
    let secondsRemaining: Int
    var reduceMotion: Bool = false
    var size: CGFloat = 40

    var body: some View {
        if reduceMotion {
            Text("\(secondsRemaining)s")
                .monoContent(13, weight: .semibold)
                .foregroundStyle(Palette.brass)
        } else {
            ZStack {
                Circle().stroke(Palette.brass.opacity(0.18), lineWidth: 3)
                Circle()
                    .trim(from: 0, to: fraction)
                    .stroke(Palette.brass, style: .init(lineWidth: 3, lineCap: .round))
                    .rotationEffect(.degrees(-90))
                Text("\(secondsRemaining)")
                    .monoContent(12, weight: .semibold)
                    .foregroundStyle(Palette.brass)
            }
            .frame(width: size, height: size)
        }
    }
}

/// A decision-colored dot for the history table.
struct DecisionDot: View {
    let decision: Decision
    private var tone: StateTone {
        switch decision {
        case .approved: return .approved
        case .denied: return .denied
        case .expired: return .expired
        }
    }
    var body: some View {
        HStack(spacing: 5) {
            Circle().fill(tone.color).frame(width: 7, height: 7)
            Text(decision.rawValue.capitalized)
                .font(.system(size: 11, weight: .medium))
                .foregroundStyle(tone.color)
        }
    }
}

/// A calm error strip. No alerts, no exclamation; the brief's voice.
struct ErrorStrip: View {
    let message: String
    var body: some View {
        HStack(spacing: 8) {
            Image(systemName: "exclamationmark.triangle")
                .foregroundStyle(Palette.brass)
            Text(message).font(.system(size: 11)).foregroundStyle(.secondary)
            Spacer()
        }
        .padding(.horizontal, 12).padding(.vertical, 8)
        .glassPanel(cornerRadius: 10, tint: Palette.brass)
    }
}

/// Relative-time helper for "4m ago" style labels, mono.
func relativeShort(_ date: Date, now: Date = Date()) -> String {
    let s = Int(now.timeIntervalSince(date))
    if s < 60 { return "\(max(0, s))s ago" }
    if s < 3600 { return "\(s / 60)m ago" }
    if s < 86_400 { return "\(s / 3600)h ago" }
    return "\(s / 86_400)d ago"
}

func clockRemaining(_ seconds: TimeInterval) -> String {
    let s = Int(seconds.rounded())
    return String(format: "%d:%02d", s / 60, s % 60)
}
