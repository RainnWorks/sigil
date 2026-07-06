Pod::Spec.new do |s|
  s.name           = 'LatchSe'
  s.version        = '1.0.0'
  s.summary        = 'Latch Secure Enclave P-256 key-agreement (threshold v2 phone share).'
  s.description    = 'The phone half of the v2 threshold: a non-exportable Secure Enclave P-256 KeyAgreement key f, minted under Face ID, that emits only x(f·E) per request. The private scalar never leaves the enclave.'
  s.author         = 'Latch'
  s.homepage       = 'https://rowm.co'
  s.license        = { :type => 'MIT' }
  s.platforms      = { :ios => '16.4' }
  s.swift_version  = '5.9'
  s.source         = { git: '' }
  s.static_framework = true

  s.dependency 'ExpoModulesCore'

  s.source_files = "**/*.{h,m,swift}"
  s.pod_target_xcconfig = {
    'DEFINES_MODULE' => 'YES',
    'SWIFT_COMPILATION_MODE' => 'wholemodule'
  }
end
