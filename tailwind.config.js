/** @type {import('tailwindcss').Config} */
module.exports = {
    content: [
        "layouts/**/*.html",
    ],
    theme: {
        extend: {
            keyframes: {
                wiggle: {
                    '0%, 100%': {
                        transform: 'rotate(-3deg)'
                    },
                    '50%': {
                        transform: 'rotate(3deg)'
                    },
                }
            },
            animation: {
                wiggle: 'wiggle 5s ease-in-out infinite',
            }
        },
    },
    plugins: [],
}
