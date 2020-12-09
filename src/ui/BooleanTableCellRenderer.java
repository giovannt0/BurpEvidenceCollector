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
import javax.swing.table.TableCellRenderer;
import java.awt.*;

/**
 * Burp extension - Evidencer
 * <p>
 * Implement a cell renderer to display booleans in evidences (tick boxes)
 *
 * @author: Theo Giovanna - https://github.com/giovannt0
 */
public class BooleanTableCellRenderer extends JCheckBox implements TableCellRenderer {

    BooleanTableCellRenderer() {
        super();
        initialize();
    }

    private void initialize() {
        setOpaque(true);
        putClientProperty("JComponent.sizeVariant", "small");
        SwingUtilities.updateComponentTreeUI(this);
        setLayout(new GridBagLayout());
        setMargin(new Insets(0, 0, 0, 0));
        setHorizontalAlignment(JLabel.CENTER);
        setBorderPainted(true);
    }

    @Override
    public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
        EvidencerTableModel evidencerTableModel = (EvidencerTableModel) table.getModel();
        Color selectedColor = Utils.getColorFromString(evidencerTableModel.getColorForRow(row));
        if (isSelected && selectedColor == Color.WHITE) {
            setBackground(UIManager.getColor("Tree.selectionBackground"));
        } else {
            setBackground(selectedColor);
        }
        if (value instanceof Boolean) {
            setSelected((Boolean) value);
        }
        return this;
    }
}
