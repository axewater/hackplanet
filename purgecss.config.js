module.exports = {
    content: [
      './modules/templates/**/*.html',
      './static/**/*.js'  // If you have any JavaScript files that use CSS classes
    ],
    css: ['./modules/static/css/**/*.css'],
    output: './modules/static/css/purged/',
    safelist: ['your-safe-class'],  // Add any classes you want to always keep
    defaultExtractor: content => content.match(/[\w-/:]+(?<!:)/g) || []
  }