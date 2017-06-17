from Renderer import Renderer
from skin import parseColor, parseFont
from enigma import eWidget, eCanvas, eLabel, eTimer, eRect, ePoint, eSize, gRGB, gFont, RT_HALIGN_LEFT, RT_HALIGN_CENTER, RT_HALIGN_RIGHT, RT_HALIGN_BLOCK, RT_VALIGN_TOP, RT_VALIGN_CENTER, RT_VALIGN_BOTTOM, RT_WRAP
NONE = 0
RUNNING = 1
SWIMMING = 2
AUTO = 3
LEFT = 0
RIGHT = 1
TOP = 2
BOTTOM = 3
CENTER = 2
BLOCK = 3

class AXBlueRunningText(Renderer):

    def __init__(self):
        Renderer.__init__(self)
        self.type = NONE
        self.txfont = gFont('Regular', 14)
        self.soffset = (0, 0)
        self.txtflags = 0
        self.txtext = ''
        self.scroll_label = self.mTimer = self.mStartPoint = None
        self.X = self.Y = self.W = self.H = self.mStartDelay = 0
        self.mAlways = 1
        self.mStep = 1
        self.mStepTimeout = 50
        self.direction = LEFT
        self.mLoopTimeout = self.mOneShot = 0
        self.mRepeat = 0
        self.mPageDelay = self.mPageLength = 0
        self.lineHeight = 0
        self.mShown = 0
        return

    GUI_WIDGET = eWidget

    def postWidgetCreate(self, instance):
        for attrib, value in self.skinAttributes:
            if attrib == 'size':
                x, y = value.split(',')
                self.W, self.H = int(x), int(y)

        self.instance.move(ePoint(0, 0))
        self.instance.resize(eSize(self.W, self.H))
        self.scroll_label = eLabel(instance)
        self.mTimer = eTimer()
        self.mTimer.callback.append(self.movingLoop)

    def preWidgetRemove(self, instance):
        self.mTimer.stop()
        self.mTimer.callback.remove(self.movingLoop)
        self.mTimer = None
        self.scroll_label = None
        return

    def applySkin(self, desktop, screen):

        def retValue(val, limit, default, Min = False):
            try:
                if Min:
                    x = min(limit, int(val))
                else:
                    x = max(limit, int(val))
            except:
                x = default

            return x

        def setWrapFlag(attrib, value):
            if attrib.lower() == 'wrap' and value == '0' or attrib.lower() == 'nowrap' and value != '0':
                self.txtflags &= ~RT_WRAP
            else:
                self.txtflags |= RT_WRAP

        self.halign = valign = eLabel.alignLeft
        if self.skinAttributes:
            attribs = []
            for attrib, value in self.skinAttributes:
                if attrib == 'font':
                    self.txfont = parseFont(value, ((1, 1), (1, 1)))
                elif attrib == 'foregroundColor':
                    self.scroll_label.setForegroundColor(parseColor(value))
                elif attrib in ('shadowColor', 'borderColor'):
                    self.scroll_label.setShadowColor(parseColor(value))
                elif attrib == 'shadowOffset':
                    x, y = value.split(',')
                    self.soffset = (int(x), int(y))
                    self.scroll_label.setShadowOffset(ePoint(self.soffset))
                elif attrib == 'borderWidth':
                    self.soffset = (-int(value), -int(value))
                elif attrib == 'valign' and value in ('top', 'center', 'bottom'):
                    valign = {'top': eLabel.alignTop,
                     'center': eLabel.alignCenter,
                     'bottom': eLabel.alignBottom}[value]
                    self.txtflags |= {'top': RT_VALIGN_TOP,
                     'center': RT_VALIGN_CENTER,
                     'bottom': RT_VALIGN_BOTTOM}[value]
                elif attrib == 'halign' and value in ('left', 'center', 'right', 'block'):
                    self.halign = {'left': eLabel.alignLeft,
                     'center': eLabel.alignCenter,
                     'right': eLabel.alignRight,
                     'block': eLabel.alignBlock}[value]
                    self.txtflags |= {'left': RT_HALIGN_LEFT,
                     'center': RT_HALIGN_CENTER,
                     'right': RT_HALIGN_RIGHT,
                     'block': RT_HALIGN_BLOCK}[value]
                elif attrib == 'noWrap':
                    setWrapFlag(attrib, value)
                elif attrib == 'options':
                    options = value.split(',')
                    for o in options:
                        if o.find('=') != -1:
                            opt, val = (x.strip() for x in o.split('=', 1))
                        else:
                            opt, val = o.strip(), ''
                        if opt == '':
                            continue
                        elif opt in ('wrap', 'nowrap'):
                            setWrapFlag(opt, val)
                        elif opt == 'movetype' and val in ('none', 'running', 'swimming'):
                            self.type = {'none': NONE,
                             'running': RUNNING,
                             'swimming': SWIMMING}[val]
                        elif opt == 'direction' and val in ('left', 'right', 'top', 'bottom'):
                            self.direction = {'left': LEFT,
                             'right': RIGHT,
                             'top': TOP,
                             'bottom': BOTTOM}[val]
                        elif opt == 'step' and val:
                            self.mStep = retValue(val, 1, self.mStep)
                        elif opt == 'steptime' and val:
                            self.mStepTimeout = retValue(val, 25, self.mStepTimeout)
                        elif opt == 'startdelay' and val:
                            self.mStartDelay = retValue(val, 0, self.mStartDelay)
                        elif opt == 'pause' and val:
                            self.mLoopTimeout = retValue(val, 0, self.mLoopTimeout)
                        elif opt == 'oneshot' and val:
                            self.mOneShot = retValue(val, 0, self.mOneShot)
                        elif opt == 'repeat' and val:
                            self.mRepeat = retValue(val, 0, self.mRepeat)
                        elif opt == 'always' and val:
                            self.mAlways = retValue(val, 0, self.mAlways)
                        elif opt == 'startpoint' and val:
                            self.mStartPoint = int(val)
                        elif opt == 'pagedelay' and val:
                            self.mPageDelay = retValue(val, 0, self.mPageDelay)
                        elif opt == 'pagelength' and val:
                            self.mPageLength = retValue(val, 0, self.mPageLength)

                else:
                    attribs.append((attrib, value))
                    if attrib == 'backgroundColor':
                        self.scroll_label.setBackgroundColor(parseColor(value))
                    elif attrib == 'transparent':
                        self.scroll_label.setTransparent(int(value))

            self.skinAttributes = attribs
        ret = Renderer.applySkin(self, desktop, screen)
        if self.mOneShot:
            self.mOneShot = max(self.mStepTimeout, self.mOneShot)
        if self.mLoopTimeout:
            self.mLoopTimeout = max(self.mStepTimeout, self.mLoopTimeout)
        if self.mPageDelay:
            self.mPageDelay = max(self.mStepTimeout, self.mPageDelay)
        self.scroll_label.setFont(self.txfont)
        if not self.txtflags & RT_WRAP:
            self.scroll_label.setNoWrap(1)
        self.scroll_label.setVAlign(valign)
        self.scroll_label.setHAlign(self.halign)
        self.scroll_label.move(ePoint(0, 0))
        self.scroll_label.resize(eSize(self.W, self.H))
        if self.direction in (TOP, BOTTOM):
            from enigma import fontRenderClass
            flh = int(fontRenderClass.getInstance().getLineHeight(self.txfont) or self.txfont.pointSize / 6 + self.txfont.pointSize)
            self.scroll_label.setText('WQq')
            if flh > self.scroll_label.calculateSize().height():
                self.lineHeight = flh
            self.scroll_label.setText('')
        return ret

    def doSuspend(self, suspended):
        self.mShown = 1 - suspended
        if suspended:
            self.changed((self.CHANGED_CLEAR,))
        else:
            self.changed((self.CHANGED_DEFAULT,))

    def connect(self, source):
        Renderer.connect(self, source)

    def changed(self, what):
        if self.mTimer is not None:
            self.mTimer.stop()
        if what[0] == self.CHANGED_CLEAR:
            self.txtext = ''
            if self.instance:
                self.scroll_label.setText('')
        elif self.mShown:
            self.txtext = self.source.text or ''
            if self.instance and not self.calcMoving():
                self.scroll_label.resize(eSize(self.W, self.H))
                self.moveLabel(self.X, self.Y)
        return

    def moveLabel(self, X, Y):
        self.scroll_label.move(ePoint(X - self.soffset[0], Y - self.soffset[1]))

    def calcMoving(self):
        self.X = self.Y = 0
        if not self.txtflags & RT_WRAP:
            self.txtext = self.txtext.replace('\xe0\x8a', ' ').replace(chr(138), ' ').replace('\n', ' ').replace('\r', ' ')
        self.scroll_label.setText(self.txtext)
        if self.txtext == '' or self.type == NONE or self.scroll_label is None:
            return False
        else:
            if self.direction in (LEFT, RIGHT) or not self.txtflags & RT_WRAP:
                self.scroll_label.resize(eSize(self.txfont.pointSize * len(self.txtext), self.H))
            text_size = self.scroll_label.calculateSize()
            text_width = text_size.width()
            text_height = text_size.height()
            if self.direction in (LEFT, RIGHT) or not self.txtflags & RT_WRAP:
                text_width += 10
            self.mStop = None
            if self.lineHeight and self.direction in (TOP, BOTTOM):
                text_height = max(text_height, (text_height + self.lineHeight - 1) / self.lineHeight * self.lineHeight)
            if self.direction in (LEFT, RIGHT):
                if not self.mAlways and text_width <= self.W:
                    return False
                if self.type == RUNNING:
                    self.A = self.X - text_width - self.soffset[0] - abs(self.mStep)
                    self.B = self.W - self.soffset[0] + abs(self.mStep)
                    if self.direction == LEFT:
                        self.mStep = -abs(self.mStep)
                        self.mStop = self.X
                        self.P = self.B
                    else:
                        self.mStep = abs(self.mStep)
                        self.mStop = self.B - text_width + self.soffset[0] - self.mStep
                        self.P = self.A
                    if self.mStartPoint is not None:
                        if self.direction == LEFT:
                            self.mStop = self.P = max(self.A, min(self.W, self.mStartPoint))
                        else:
                            self.mStop = self.P = max(self.A, min(self.B, self.mStartPoint - text_width + self.soffset[0]))
                elif self.type == SWIMMING:
                    if text_width < self.W:
                        self.A = self.X + 1
                        self.B = self.W - text_width - 1
                        if self.halign == LEFT:
                            self.P = self.A
                            self.mStep = abs(self.mStep)
                        elif self.halign == RIGHT:
                            self.P = self.B
                            self.mStep = -abs(self.mStep)
                        else:
                            self.P = int(self.B / 2)
                            self.mStep = self.direction == RIGHT and abs(self.mStep) or -abs(self.mStep)
                    else:
                        if text_width == self.W:
                            text_width += max(2, text_width / 20)
                        self.A = self.W - text_width
                        self.B = self.X
                        if self.halign == LEFT:
                            self.P = self.B
                            self.mStep = -abs(self.mStep)
                        elif self.halign == RIGHT:
                            self.P = self.A
                            self.mStep = abs(self.mStep)
                        else:
                            self.P = int(self.A / 2)
                            self.mStep = self.direction == RIGHT and abs(self.mStep) or -abs(self.mStep)
                else:
                    return False
            elif self.direction in (TOP, BOTTOM):
                if not self.mAlways and text_height <= self.H:
                    return False
                if self.type == RUNNING:
                    self.A = self.Y - text_height - self.soffset[1] - abs(self.mStep)
                    self.B = self.H - self.soffset[1] + abs(self.mStep)
                    if self.direction == TOP:
                        self.mStep = -abs(self.mStep)
                        self.mStop = self.Y
                        self.P = self.B
                    else:
                        self.mStep = abs(self.mStep)
                        self.mStop = self.B - text_height + self.soffset[1] - self.mStep
                        self.P = self.A
                    if self.mStartPoint is not None:
                        if self.direction == TOP:
                            self.mStop = self.P = max(self.A, min(self.H, self.mStartPoint))
                        else:
                            self.mStop = self.P = max(self.A, min(self.B, self.mStartPoint - text_height + self.soffset[1]))
                elif self.type == SWIMMING:
                    if text_height < self.H:
                        self.A = self.Y
                        self.B = self.H - text_height
                        if self.direction == TOP:
                            self.P = self.B
                            self.mStep = -abs(self.mStep)
                        else:
                            self.P = self.A
                            self.mStep = abs(self.mStep)
                    else:
                        if text_height == self.H:
                            text_height += max(2, text_height / 40)
                        self.A = self.H - text_height
                        self.B = self.Y
                        if self.direction == TOP:
                            self.P = self.B
                            self.mStep = -abs(self.mStep)
                            self.mStop = self.B
                        else:
                            self.P = self.A
                            self.mStep = abs(self.mStep)
                            self.mStop = self.A
                else:
                    return False
            else:
                return False
            self.xW = max(self.W, text_width)
            self.xH = max(self.H, text_height)
            self.scroll_label.resize(eSize(self.xW, self.xH))
            if self.mStartDelay:
                if self.direction in (LEFT, RIGHT):
                    self.moveLabel(self.P, self.Y)
                else:
                    self.moveLabel(self.X, self.P)
            self.mCount = self.mRepeat
            self.mTimer.start(self.mStartDelay, True)
            return True

    def movingLoop(self):
        if self.A <= self.P <= self.B:
            if self.direction in (LEFT, RIGHT):
                self.moveLabel(self.P, self.Y)
            else:
                self.moveLabel(self.X, self.P)
            timeout = self.mStepTimeout
            if self.mStop != None and self.mStop + abs(self.mStep) > self.P >= self.mStop:
                if self.type == RUNNING and self.mOneShot > 0:
                    if self.mRepeat > 0 and self.mCount - 1 <= 0:
                        return
                    timeout = self.mOneShot
                elif self.type == SWIMMING and self.mPageLength > 0 and self.mPageDelay > 0:
                    if self.direction == TOP and self.mStep < 0:
                        self.mStop -= self.mPageLength
                        if self.mStop < self.A:
                            self.mStop = self.B
                        timeout = self.mPageDelay
                    elif self.direction == BOTTOM and self.mStep > 0:
                        self.mStop += self.mPageLength
                        if self.mStop > self.B:
                            self.mStop = self.A
                        timeout = self.mPageDelay
        else:
            if self.mRepeat > 0:
                self.mCount -= 1
                if self.mCount == 0:
                    return
            timeout = self.mLoopTimeout
            if self.type == RUNNING:
                if self.P < self.A:
                    self.P = self.B + abs(self.mStep)
                else:
                    self.P = self.A - abs(self.mStep)
            else:
                self.mStep = -self.mStep
        self.P += self.mStep
        self.mTimer.start(timeout, True)
        return