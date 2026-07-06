//  Glass.swift
//  Liquid Glass adoption, kept to the navigation/control layer per the HIG:
//  glass floats over content, content itself stays on plain grouped surfaces.
//  These helpers are the only place glass is applied, so the rule is enforced
//  in one spot rather than sprinkled through the views.

import SwiftUI

extension View {
    /// A floating control surface: a card of chrome that sits above content.
    /// Regular glass in a native squircle. No custom re-rounding of controls;
    /// this is only for container chrome (fix-it bars, the menubar panel).
    func glassPanel(cornerRadius: CGFloat = 14, tint: Color? = nil) -> some View {
        let glass: Glass = tint.map { .regular.tint($0.opacity(0.16)) } ?? .regular
        return self.glassEffect(glass, in: .rect(cornerRadius: cornerRadius))
    }

    /// An interactive glass chip (a tappable pill in the control layer).
    func glassChip(tint: Color? = nil) -> some View {
        let base: Glass = tint.map { .regular.tint($0.opacity(0.22)) } ?? .regular
        return self.glassEffect(base.interactive(), in: .capsule)
    }
}

/// The one bespoke control the brief allows: a full-radius capsule for the most
/// important interaction. On the Mac that is the menubar Approve. It is glass,
/// tinted sea-green, and it is the only place we depart from stock button chrome.
struct ApproveCapsule: View {
    let title: String
    let enabled: Bool
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            Label(title, systemImage: "touchid")
                .font(.system(size: 13, weight: .semibold))
                .frame(maxWidth: .infinity)
                .padding(.vertical, 8)
        }
        .buttonStyle(.plain)
        .foregroundStyle(enabled ? Palette.seaGreen : Color.secondary)
        .glassEffect(
            .regular.tint(Palette.seaGreen.opacity(enabled ? 0.24 : 0.06)).interactive(),
            in: .capsule
        )
        .disabled(!enabled)
    }
}
