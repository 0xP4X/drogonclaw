package tui

const (
	contentPadding  = 1
	headerHeight    = 1
	footerHeight    = 1
	inputMinHeight  = 1
	spacerMinHeight = 0
	sidebarMaxWidth = 36
	sidebarMinWidth = 24
	sidebarPadX     = 1
	sidebarGap      = 1
)

type tuiLayout struct {
	width         int
	height        int
	mainWidth     int
	mainHeight    int
	sidebarWidth  int
	sidebarHeight int
	contentWidth  int
	contentHeight int
	inputHeight   int
	headerHeight  int
	footerHeight  int
	hasSidebar    bool
	isCompact     bool
}

func calculateLayout(width, height, fixedHeight int) tuiLayout {
	width = max(1, width)
	height = max(1, height)

	if fixedHeight == 0 {
		fixedHeight = headerHeight + footerHeight + inputMinHeight
	}

	l := tuiLayout{
		width:        width,
		height:       height,
		hasSidebar:   false,
		isCompact:    width < 80,
		headerHeight: headerHeight,
		footerHeight: footerHeight,
		inputHeight:  fixedHeight,
	}

	l.mainWidth = width
	l.mainHeight = max(1, height-fixedHeight)
	l.contentWidth = max(8, l.mainWidth-contentPadding*2)
	l.contentHeight = max(3, l.mainHeight)

	return l
}

func calculateLayoutWithSidebar(width, height int, showSidebar bool) tuiLayout {
	width = max(1, width)
	height = max(1, height)

	l := tuiLayout{
		width:        width,
		height:       height,
		hasSidebar:   showSidebar,
		isCompact:    width < 80,
		headerHeight: headerHeight,
		footerHeight: footerHeight,
		inputHeight:  1,
	}

	// View() layout: header(1) + hline(1) + content + hline(1) + status(1) + hline(1) + input(1) = 6 fixed lines
	reservedLines := 6

	if showSidebar && width >= sidebarMinWidth+20 {
		l.sidebarWidth = min(sidebarMaxWidth, width/3) + sidebarPadX*2 + 1
		l.sidebarHeight = max(1, height-reservedLines)
		l.mainWidth = width - l.sidebarWidth - sidebarGap
		l.mainHeight = max(1, height-reservedLines)
	} else {
		l.hasSidebar = false
		l.sidebarWidth = 0
		l.sidebarHeight = 0
		l.mainWidth = width
		l.mainHeight = max(1, height-reservedLines)
	}

	l.contentWidth = max(8, l.mainWidth-contentPadding*2)
	l.contentHeight = max(3, l.mainHeight)

	return l
}

func clamp(value, minValue, maxValue int) int {
	if value < minValue {
		return minValue
	}
	if value > maxValue {
		return maxValue
	}
	return value
}

func (l tuiLayout) mainPaneBounds() (width, height int) {
	return l.contentWidth, l.contentHeight
}

func (l tuiLayout) sidebarBounds() (width, height int) {
	return l.sidebarWidth, l.sidebarHeight
}

func (l tuiLayout) headerBounds() (width, height int) {
	return l.width, l.headerHeight
}

func (l tuiLayout) statusBounds() (width, height int) {
	return l.width, l.footerHeight
}

func (l tuiLayout) inputBounds() (width, height int) {
	return l.width, l.inputHeight
}
