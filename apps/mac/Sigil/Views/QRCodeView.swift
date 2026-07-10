//  QRCodeView.swift
//  Native QR rendering via CoreImage. No third-party QR dependency. The payload
//  is the pairing base64; it moves optically so the phone pins the daemon keys
//  with certainty (docs/design/pairing.md).

import SwiftUI
import CoreImage.CIFilterBuiltins

struct QRCodeView: View {
    let payload: String
    var side: CGFloat = 200

    var body: some View {
        Group {
            if let image = Self.render(payload) {
                Image(nsImage: image)
                    .interpolation(.none)
                    .resizable()
                    .scaledToFit()
            } else {
                RoundedRectangle(cornerRadius: 8).fill(.background.secondary)
                    .overlay(Text("QR unavailable").font(.system(size: 11)).foregroundStyle(.secondary))
            }
        }
        .frame(width: side, height: side)
        .padding(12)
        .background(.white, in: .rect(cornerRadius: 12))
    }

    /// Render `text` to a crisp QR NSImage. High correction so it survives a
    /// couch-distance camera.
    static func render(_ text: String) -> NSImage? {
        let filter = CIFilter.qrCodeGenerator()
        filter.message = Data(text.utf8)
        filter.correctionLevel = "H"
        guard let output = filter.outputImage else { return nil }
        let scale = output.transformed(by: CGAffineTransform(scaleX: 12, y: 12))
        let context = CIContext()
        guard let cg = context.createCGImage(scale, from: scale.extent) else { return nil }
        return NSImage(cgImage: cg, size: NSSize(width: scale.extent.width, height: scale.extent.height))
    }
}

#Preview {
    QRCodeView(payload: Fixtures.qrPayloadBase64).padding()
}
