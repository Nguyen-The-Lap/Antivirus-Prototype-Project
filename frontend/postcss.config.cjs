module.exports = {
  plugins: [
    require('postcss-import'),
    require('postcss-nesting'),
    require('@tailwindcss/postcss7-compat'),
    require('autoprefixer'),
  ],
}
