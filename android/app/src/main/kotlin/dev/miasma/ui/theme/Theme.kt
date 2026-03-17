package dev.miasma.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

// Miasma colour palette — dark teal accent on near-black background.
private val DarkColors = darkColorScheme(
    primary          = Color(0xFF4DB6AC),   // teal 300
    onPrimary        = Color(0xFF00251A),
    primaryContainer = Color(0xFF00695C),
    background       = Color(0xFF121212),
    surface          = Color(0xFF1E1E1E),
    error            = Color(0xFFCF6679),
)

private val LightColors = lightColorScheme(
    primary          = Color(0xFF00695C),   // teal 700
    onPrimary        = Color.White,
    primaryContainer = Color(0xFFB2DFDB),
    background       = Color(0xFFF5F5F5),
    surface          = Color.White,
    error            = Color(0xFFB00020),
)

@Composable
fun MiasmaTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    content: @Composable () -> Unit,
) {
    MaterialTheme(
        colorScheme = if (darkTheme) DarkColors else LightColors,
        content = content,
    )
}
