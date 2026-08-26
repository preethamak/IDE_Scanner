const vscode = require('vscode');

// Thin inline-completion client: contributes no chatParticipants/languageModelTools,
// so manifest-level agentic detection alone misses it. The code-level API
// emitter must classify it as an AI assistant surface.
class CompletionProvider {
  provideInlineCompletions(document, position, context, token) {
    return { items: [] };
  }

  freeInlineCompletions() {}
}

function activate(context) {
  context.subscriptions.push(
    vscode.languages.registerInlineCompletionItemProvider(
      { scheme: 'file' },
      new CompletionProvider()
    )
  );
}

module.exports = { activate };
