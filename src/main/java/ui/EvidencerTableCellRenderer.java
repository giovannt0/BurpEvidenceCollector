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
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;
import java.text.SimpleDateFormat;
import java.util.Date;

/**
 * Burp extension - Evidencer
 * <p>
 * Custom renderer to render the entries in the JTable, i.e. the evidences.
 * This is where e.g. highlighting is handled
 *
 * @author: Theo Giovanna - https://github.com/giovannt0
 */
class EvidencerTableCellRenderer extends DefaultTableCellRenderer {

    @Override
    protected void setValue(Object value) {
        if (value instanceof Date) {
            value = new SimpleDateFormat("HH:mm:ss d MMM yyyy").format(value);
        }
        if ((value instanceof Integer) && ((Integer) value == -1)) {
            value = "";
        }
        super.setValue(value);
    }

    @Override
    public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
        EvidencerTableModel evidencerTableModel = (EvidencerTableModel) table.getModel();
        Component component = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
        Color backgroundColor = Utils.getColorFromString(evidencerTableModel.getColorForRow(row));
        Color foregroundColor = Utils.getColorFromString(evidencerTableModel.getFontColorForRow(row));
        if (isSelected && backgroundColor == Color.WHITE) {
            component.setBackground(UIManager.getColor("Tree.selectionBackground"));
        } else {
            component.setBackground(backgroundColor);
        }
        component.setForeground(foregroundColor);
        return component;
    }

}
