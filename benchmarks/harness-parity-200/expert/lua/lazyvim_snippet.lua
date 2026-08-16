-- SPDX-License-Identifier: Apache-2.0

-- Run from the LazyVim checkout with lua/ on package.path.
vim = vim or {}
vim.lsp = vim.lsp or {}
vim.lsp._snippet_grammar = vim.lsp._snippet_grammar or {
  parse = function() error("use fallback parser") end,
}

local cmp = require("lazyvim.util.cmp")

function fuzz(data)
  return cmp.snippet_fix(data)
end
