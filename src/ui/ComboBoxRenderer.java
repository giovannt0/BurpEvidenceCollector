/*
 * Copyright (C) 2020 Theo Giovanna.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package ui;

import evidencer.Utils;

import javax.swing.*;
import java.awt.*;

/**
 * Burp extension - Evidencer
 * <p>
 * Implement a ListCellRenderer for the highlight dropdown menu
 *
 * @author: Theo Giovanna - https://github.com/giovannt0
 */
public class ComboBoxRenderer extends JPanel implements ListCellRenderer {

    private Color[] colors = Utils.COLORS;
    private JLabel text;

    ComboBoxRenderer(JComboBox comboBox) {
        JPanel textPanel = new JPanel();
        textPanel.add(this);
        text = new JLabel();
        text.setOpaque(true);
        text.setFont(comboBox.getFont());
        textPanel.add(text);
    }

    @Override
    public Component getListCellRendererComponent(JList list, Object value, int index, boolean isSelected, boolean cellHasFocus) {
        text.setText(value.toString());
        if (index > -1) {
            Color color = colors[index];
            text.setBackground(color);
            // If selected color is red or blue, change the font color to enhance readability
            text.setForeground(Utils.getColorFromString(Utils.getForegroundColorFromHighlightColor(color.toString())));
        }
        return text;
    }
}
