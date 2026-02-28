// Color extraction and manipulation utilities
// Uses colorthief for palette extraction

/**
 * Convert RGB to HSL
 */
export function rgbToHsl(r: number, g: number, b: number): [number, number, number] {
    r /= 255
    g /= 255
    b /= 255

    const max = Math.max(r, g, b)
    const min = Math.min(r, g, b)
    let h = 0
    let s = 0
    const l = (max + min) / 2

    if (max !== min) {
        const d = max - min
        s = l > 0.5 ? d / (2 - max - min) : d / (max + min)

        switch (max) {
            case r:
                h = ((g - b) / d + (g < b ? 6 : 0)) / 6
                break
            case g:
                h = ((b - r) / d + 2) / 6
                break
            case b:
                h = ((r - g) / d + 4) / 6
                break
        }
    }

    return [h * 360, s * 100, l * 100]
}

/**
 * Convert HSL to RGB
 */
export function hslToRgb(h: number, s: number, l: number): [number, number, number] {
    h /= 360
    s /= 100
    l /= 100

    let r, g, b

    if (s === 0) {
        r = g = b = l
    } else {
        const hue2rgb = (p: number, q: number, t: number) => {
            if (t < 0) t += 1
            if (t > 1) t -= 1
            if (t < 1 / 6) return p + (q - p) * 6 * t
            if (t < 1 / 2) return q
            if (t < 2 / 3) return p + (q - p) * (2 / 3 - t) * 6
            return p
        }

        const q = l < 0.5 ? l * (1 + s) : l + s - l * s
        const p = 2 * l - q
        r = hue2rgb(p, q, h + 1 / 3)
        g = hue2rgb(p, q, h)
        b = hue2rgb(p, q, h - 1 / 3)
    }

    return [Math.round(r * 255), Math.round(g * 255), Math.round(b * 255)]
}

/**
 * Convert RGB to hex string
 */
export function rgbToHex(r: number, g: number, b: number): string {
    return '#' + [r, g, b].map(x => x.toString(16).padStart(2, '0')).join('')
}

/**
 * Check if a color should be filtered out (too white, too black, or too gray)
 */
export function shouldFilterColor(r: number, g: number, b: number): boolean {
    const [, saturation, lightness] = rgbToHsl(r, g, b)

    // Filter out colors that are:
    // - Too white (lightness > 90%)
    // - Too black (lightness < 10%)
    // - Too gray/neutral (saturation < 15%)
    return lightness > 90 || lightness < 10 || saturation < 15
}

/**
 * Get saturation of a color (used for picking most vibrant)
 */
export function getColorSaturation(r: number, g: number, b: number): number {
    const [, saturation] = rgbToHsl(r, g, b)
    return saturation
}

/**
 * Generate light mode background color from a base color
 * Keeps hue and reduces saturation, increases lightness to ~85%
 */
export function generateLightModeColor(r: number, g: number, b: number): string {
    const [h, s] = rgbToHsl(r, g, b)
    // Light mode: high lightness (85%), moderate saturation (keep some color)
    const newS = Math.min(s, 60) // Cap saturation for softer look
    const [newR, newG, newB] = hslToRgb(h, newS, 88)
    return rgbToHex(newR, newG, newB)
}

/**
 * Generate dark mode background color from a base color
 * Keeps hue and reduces saturation, decreases lightness to ~25%
 */
export function generateDarkModeColor(r: number, g: number, b: number): string {
    const [h, s] = rgbToHsl(r, g, b)
    // Dark mode: low lightness (25%), moderate saturation
    const newS = Math.min(s, 50) // Cap saturation for subtler look
    const [newR, newG, newB] = hslToRgb(h, newS, 22)
    return rgbToHex(newR, newG, newB)
}

/**
 * Extract dominant color from an image element (client-side)
 * Returns both light and dark mode background colors, or null if no valid color found
 */
export async function extractColorsFromImage(
    imgElement: HTMLImageElement
): Promise<{ colorLight: string; colorDark: string } | null> {
    try {
        // Dynamically import colorthief (works in browser)
        const ColorThief = (await import('colorthief')).default

        const colorThief = new ColorThief()

        // Wait for image to load if not already loaded
        if (!imgElement.complete) {
            await new Promise<void>((resolve, reject) => {
                imgElement.onload = () => resolve()
                imgElement.onerror = () => reject(new Error('Image failed to load'))
            })
        }

        // Get palette of 8 colors
        let palette: [number, number, number][]
        try {
            palette = colorThief.getPalette(imgElement, 8)
        } catch {
            // If palette fails, try getting single dominant color
            const dominant = colorThief.getColor(imgElement)
            palette = [dominant]
        }

        if (!palette || palette.length === 0) {
            return null
        }

        // Filter out white/black/gray colors
        const validColors = palette.filter(([r, g, b]) => !shouldFilterColor(r, g, b))

        // If all colors were filtered, try the original palette with relaxed criteria
        let selectedColor: [number, number, number]
        if (validColors.length === 0) {
            // Fall back to most saturated color from original palette
            const sortedBysat = [...palette].sort(
                (a, b) => getColorSaturation(b[0], b[1], b[2]) - getColorSaturation(a[0], a[1], a[2])
            )
            selectedColor = sortedBysat[0]

            // If even the most saturated is very gray, return null
            if (getColorSaturation(selectedColor[0], selectedColor[1], selectedColor[2]) < 5) {
                return null
            }
        } else {
            // Pick the most saturated valid color (most "brand-like")
            validColors.sort(
                (a, b) => getColorSaturation(b[0], b[1], b[2]) - getColorSaturation(a[0], a[1], a[2])
            )
            selectedColor = validColors[0]
        }

        const [r, g, b] = selectedColor
        return {
            colorLight: generateLightModeColor(r, g, b),
            colorDark: generateDarkModeColor(r, g, b),
        }
    } catch (error) {
        console.error('Color extraction failed:', error)
        return null
    }
}



