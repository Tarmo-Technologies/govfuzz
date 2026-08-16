# SPDX-License-Identifier: Apache-2.0

# frozen_string_literal: true

require "bundler/setup"
require "tempfile"
require "tmuxinator"

def fuzz(data)
  Tempfile.create(["tmuxinator-fuzz", ".yml"]) do |file|
    file.binmode
    file.write(data)
    file.flush
    begin
      Tmuxinator::Project.load(file.path)
    rescue RuntimeError, Psych::Exception
      # Invalid configuration is expected input rejection.
    end
  end
end
