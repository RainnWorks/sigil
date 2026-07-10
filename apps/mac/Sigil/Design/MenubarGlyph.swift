//  MenubarGlyph.swift
//  The four menubar states, distinguished by SHAPE so they survive the menu
//  bar's monochrome template rendering (the brief's hard requirement). Color is
//  never load-bearing here; each state is a different silhouette:
//
//    idle     dotted diamond outline   (daemon down or unpaired)
//    armed    solid diamond            (the sigil set; requests will route)
//    pending  solid diamond + badge    (a corner notch, a decision waiting)
//    locked   barred diamond           (a slash; sealed until unsealed)
//
//  Rendered as an NSImage template so AppKit tints it to match the menu bar in
//  light and dark, active and inactive.

import AppKit

enum MenubarState: String, CaseIterable, Sendable {
    case idle
    case armed
    case pending
    case locked
}

enum MenubarGlyph {
    /// A template NSImage for the given state, sized for the menu bar (18pt).
    static func image(for state: MenubarState) -> NSImage {
        let size = NSSize(width: 18, height: 18)
        let image = NSImage(size: size, flipped: false) { rect in
            guard let ctx = NSGraphicsContext.current?.cgContext else { return false }
            draw(state, in: rect, ctx: ctx)
            return true
        }
        image.isTemplate = true
        image.accessibilityDescription = "Sigil \(state.rawValue)"
        return image
    }

    private static func draw(_ state: MenubarState, in rect: CGRect, ctx: CGContext) {
        let inset: CGFloat = 2.5
        let box = rect.insetBy(dx: inset, dy: inset)
        // A diamond: the sigil mark. Points at N/E/S/W.
        let cx = box.midX, cy = box.midY
        let hw = box.width / 2, hh = box.height / 2
        let diamond = CGMutablePath()
        diamond.move(to: CGPoint(x: cx, y: cy + hh))
        diamond.addLine(to: CGPoint(x: cx + hw, y: cy))
        diamond.addLine(to: CGPoint(x: cx, y: cy - hh))
        diamond.addLine(to: CGPoint(x: cx - hw, y: cy))
        diamond.closeSubpath()

        ctx.setFillColor(NSColor.black.cgColor)   // template: tinted by AppKit
        ctx.setStrokeColor(NSColor.black.cgColor)

        switch state {
        case .idle:
            // Dotted outline: present but inert.
            ctx.addPath(diamond)
            ctx.setLineWidth(1.5)
            ctx.setLineDash(phase: 0, lengths: [1.6, 1.8])
            ctx.strokePath()

        case .armed:
            // Solid: the sigil is set and listening.
            ctx.addPath(diamond)
            ctx.fillPath()

        case .pending:
            // Solid sigil with a badge notch cut into the top-right, then a
            // filled badge dot beside it: a decision waiting. Shape, not color.
            ctx.saveGState()
            ctx.addPath(diamond)
            ctx.fillPath()
            ctx.restoreGState()
            let badgeR: CGFloat = 3.4
            let badgeC = CGPoint(x: box.maxX - badgeR * 0.3, y: box.maxY - badgeR * 0.3)
            // Punch a hole so the badge reads as separate in monochrome.
            ctx.setBlendMode(.clear)
            ctx.fillEllipse(in: CGRect(x: badgeC.x - badgeR - 1.1, y: badgeC.y - badgeR - 1.1,
                                       width: (badgeR + 1.1) * 2, height: (badgeR + 1.1) * 2))
            ctx.setBlendMode(.normal)
            ctx.setFillColor(NSColor.black.cgColor)
            ctx.fillEllipse(in: CGRect(x: badgeC.x - badgeR, y: badgeC.y - badgeR,
                                       width: badgeR * 2, height: badgeR * 2))

        case .locked:
            // Barred silhouette: an outline diamond with a slash through it.
            ctx.addPath(diamond)
            ctx.setLineWidth(1.6)
            ctx.strokePath()
            ctx.setLineWidth(2.0)
            ctx.setLineCap(.round)
            ctx.move(to: CGPoint(x: box.minX + 1, y: box.minY + 1))
            ctx.addLine(to: CGPoint(x: box.maxX - 1, y: box.maxY - 1))
            ctx.strokePath()
        }
    }
}
