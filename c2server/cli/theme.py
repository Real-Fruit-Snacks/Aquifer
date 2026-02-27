"""Catppuccin Mocha palette and Rich theme for the Namespace C2 console."""

from rich.console import Console
from rich.theme import Theme

MOCHA = {
    "rosewater": "#f5e0dc",
    "flamingo":  "#f2cdcd",
    "pink":      "#f5c2e7",
    "mauve":     "#cba6f7",
    "red":       "#f38ba8",
    "maroon":    "#eba0ac",
    "peach":     "#fab387",
    "yellow":    "#f9e2af",
    "green":     "#a6e3a1",
    "teal":      "#94e2d5",
    "sky":       "#89dceb",
    "sapphire":  "#74c7ec",
    "blue":      "#89b4fa",
    "lavender":  "#b4befe",
    "text":      "#cdd6f4",
    "subtext1":  "#bac2de",
    "subtext0":  "#a6adc8",
    "overlay2":  "#9399b2",
    "overlay1":  "#7f849c",
    "overlay0":  "#6c7086",
    "surface2":  "#585b70",
    "surface1":  "#45475a",
    "surface0":  "#313244",
    "base":      "#1e1e2e",
    "mantle":    "#181825",
    "crust":     "#11111b",
}

# Build Rich Theme with semantic names
C2_THEME = Theme(
    {
        "success": f"bold {MOCHA['green']}",
        "error": f"bold {MOCHA['red']}",
        "warning": f"bold {MOCHA['yellow']}",
        "info": MOCHA["blue"],
        "prompt": f"bold {MOCHA['mauve']}",
        "prompt.session": f"bold {MOCHA['peach']}",
        "table.header": f"bold {MOCHA['lavender']}",
        "table.border": MOCHA["surface2"],
        "session.active": MOCHA["green"],
        "session.dormant": MOCHA["yellow"],
        "session.dead": MOCHA["red"],
        "implant.id": f"bold {MOCHA['peach']}",
        "hostname": f"bold {MOCHA['sapphire']}",
        "user.root": f"bold {MOCHA['red']}",
        "user.normal": MOCHA["teal"],
        "path": MOCHA["sky"],
        "timestamp": MOCHA["overlay1"],
        "panel.border": MOCHA["mauve"],
        "panel.title": f"bold {MOCHA['lavender']}",
        "output": MOCHA["text"],
        "listener.https": MOCHA["green"],
        "listener.dns": MOCHA["sapphire"],
        "key": MOCHA["flamingo"],
        "dim": MOCHA["overlay0"],
    }
)

# Singleton console used by all CLI modules
console = Console(theme=C2_THEME)
