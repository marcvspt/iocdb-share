/** @type {import('tailwindcss').Config} */
export default {
	content: ['./src/**/*.{astro,html,js,jsx,md,mdx,svelte,ts,tsx,vue}'],
	theme: {
		extend: {
			colors: {
				'accent-light': 'rgb(var(--accent-light))',
				'accent-dark': 'rgb(var(--accent-dark))',
			},
			backgroundSize: {
				'200': '200%',
			},
			backgroundPosition: {
				'0': '0%',
				'100': '100%',
			},
		},
	},
	plugins: [],
}
