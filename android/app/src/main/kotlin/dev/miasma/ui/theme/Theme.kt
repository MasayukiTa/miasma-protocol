package dev.miasma.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp

// ── Miasma colour palette ──────────────────────────────────────────────────

object MiasmaColors {
    val Teal200 = Color(0xFF80CBC4)
    val Teal300 = Color(0xFF4DB6AC)
    val Teal400 = Color(0xFF26A69A)
    val Teal700 = Color(0xFF00695C)
    val Teal900 = Color(0xFF004D40)

    val SurfaceDark = Color(0xFF141418)
    val SurfaceCard = Color(0xFF1C1C22)
    val SurfaceElevated = Color(0xFF242430)
    val DimText = Color(0xFF9E9EA8)

    val Green = Color(0xFF4CAF50)
    val Yellow = Color(0xFFFFB74D)
    val Red = Color(0xFFEF5350)
    val Blue = Color(0xFF42A5F5)

    val AccentGlow = Color(0x1A4DB6AC)  // teal at 10% alpha
}

private val DarkColors = darkColorScheme(
    primary            = MiasmaColors.Teal300,
    onPrimary          = Color(0xFF00251A),
    primaryContainer   = MiasmaColors.Teal900,
    onPrimaryContainer = MiasmaColors.Teal200,
    secondary          = MiasmaColors.Teal400,
    onSecondary        = Color.White,
    background         = MiasmaColors.SurfaceDark,
    surface            = MiasmaColors.SurfaceCard,
    surfaceVariant     = MiasmaColors.SurfaceElevated,
    onSurface          = Color(0xFFE8E8EE),
    onSurfaceVariant   = MiasmaColors.DimText,
    error              = MiasmaColors.Red,
    onError            = Color.White,
    outline            = Color(0xFF3A3A46),
    outlineVariant     = Color(0xFF2A2A34),
)

private val LightColors = lightColorScheme(
    primary            = MiasmaColors.Teal700,
    onPrimary          = Color.White,
    primaryContainer   = Color(0xFFB2DFDB),
    onPrimaryContainer = MiasmaColors.Teal900,
    secondary          = MiasmaColors.Teal400,
    background         = Color(0xFFF8F9FA),
    surface            = Color.White,
    surfaceVariant     = Color(0xFFF0F2F4),
    onSurface          = Color(0xFF1A1A2E),
    onSurfaceVariant   = Color(0xFF5E5E6E),
    error              = Color(0xFFB00020),
    outline            = Color(0xFFD0D0D8),
    outlineVariant     = Color(0xFFE8E8EC),
)

private val MiasmaTypography = Typography(
    displayLarge = TextStyle(
        fontWeight = FontWeight.Bold,
        fontSize = 32.sp,
        letterSpacing = (-0.5).sp,
    ),
    displayMedium = TextStyle(
        fontWeight = FontWeight.Bold,
        fontSize = 28.sp,
        letterSpacing = (-0.25).sp,
    ),
    headlineMedium = TextStyle(
        fontWeight = FontWeight.SemiBold,
        fontSize = 22.sp,
    ),
    headlineSmall = TextStyle(
        fontWeight = FontWeight.SemiBold,
        fontSize = 18.sp,
    ),
    titleMedium = TextStyle(
        fontWeight = FontWeight.Medium,
        fontSize = 16.sp,
        letterSpacing = 0.15.sp,
    ),
    bodyLarge = TextStyle(
        fontWeight = FontWeight.Normal,
        fontSize = 16.sp,
        lineHeight = 24.sp,
    ),
    bodyMedium = TextStyle(
        fontWeight = FontWeight.Normal,
        fontSize = 14.sp,
        lineHeight = 20.sp,
    ),
    bodySmall = TextStyle(
        fontWeight = FontWeight.Normal,
        fontSize = 12.sp,
        lineHeight = 16.sp,
    ),
    labelLarge = TextStyle(
        fontWeight = FontWeight.Medium,
        fontSize = 14.sp,
        letterSpacing = 0.1.sp,
    ),
    labelMedium = TextStyle(
        fontWeight = FontWeight.Medium,
        fontSize = 12.sp,
        letterSpacing = 0.5.sp,
    ),
    labelSmall = TextStyle(
        fontWeight = FontWeight.Normal,
        fontSize = 11.sp,
        letterSpacing = 0.5.sp,
    ),
)

@Composable
fun MiasmaTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    content: @Composable () -> Unit,
) {
    MaterialTheme(
        colorScheme = if (darkTheme) DarkColors else LightColors,
        typography = MiasmaTypography,
        content = content,
    )
}
