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

import burp.BurpExtender;
import evidencer.HttpRequestResponse;
import evidencer.Utils;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;

/**
 * Burp extension - Evidencer
 * <p>
 * Implement a TableModel with our custom fields
 *
 * @author: Theo Giovanna - https://github.com/giovannt0
 */
public class EvidencerTableModel extends AbstractTableModel {

    @Override
    public int getRowCount() {
        return Evidencer.httpRequestResponses.size();
    }

    @Override
    public int getColumnCount() {
        return 15;
    }

    @Override
    public boolean isCellEditable(int rowIndex, int columnIndex) {
        return columnIndex == 0 || columnIndex == 10 || columnIndex == 11 || columnIndex == 14;
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        switch (columnIndex) {
            case 0:
            case 5:
            case 6:
            case 7:
                return Integer.class;
            case 4:
            case 14:
                return Boolean.class;
            case 9:
                return Date.class;
            default:
                return String.class;
        }
    }

    int getPreferredWidth(int column) {
        switch (column) {
            case 0:
                return 40;
            case 1:
            case 9:
            case 10:
            case 11:
            case 12:
            case 14:
                return 150;
            case 2:
            case 4:
            case 5:
            case 6:
            case 7:
            case 8:
                return 55;
            case 3:
                return 430;
            case 13:
                return 220;
            default:
                return 20;
        }
    }

    @Override
    public String getColumnName(int column) {
        switch (column) {
            case 0:
                return "#";
            case 1:
                return "Host";
            case 2:
                return "Method";
            case 3:
                return "URL";
            case 4:
                return "Params";
            case 5:
                return "Count";
            case 6:
                return "Status";
            case 7:
                return "Length";
            case 8:
                return "MIME";
            case 9:
                return "Time";
            case 10:
                return "Comment";
            case 11:
                return "Test Objective";
            case 12:
                return "CWE";
            case 13:
                return "Description";
            case 14:
                return "Attack successful";
            default:
                return "";
        }
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        try {
            HttpRequestResponse requestResponse = Evidencer.httpRequestResponses.get(rowIndex);
            switch (columnIndex) {
                case 0:
                    return requestResponse.id;
                case 1:
                    return requestResponse.url.getProtocol() +
                            "://" +
                            requestResponse.url.getHost();
                case 2:
                    return requestResponse.method;
                case 3:
                    return requestResponse.path;
                case 4:
                    return requestResponse.hasParams;
                case 5:
                    return requestResponse.paramCount;
                case 6:
                    return requestResponse.status;
                case 7:
                    return requestResponse.length;
                case 8:
                    return requestResponse.mime;
                case 9:
                    return requestResponse.date;
                case 10:
                    return requestResponse.comment;
                case 11:
                    return requestResponse.objective;
                case 12:
                    return requestResponse.cwe;
                case 13:
                    return requestResponse.description;
                case 14:
                    return requestResponse.attackWasSuccessful;
                default:
                    return "";
            }
        } catch (Exception ex) {
            BurpExtender.stderr.println(ex.getMessage());
            return null;
        }
    }

    /**
     * This method is called whenever updating a value for an evidence entry
     *
     * @param value    the value entered by the user
     * @param rowIndex the row index
     * @param colIndex the column index
     */
    @Override
    public void setValueAt(Object value, int rowIndex, int colIndex) {
        HttpRequestResponse requestResponse = Evidencer
                .httpRequestResponses
                .get(rowIndex);

        // Pushing old evidence to the undo stack
        if (requestResponse.getValueAtColumn(colIndex) != value) {
            Utils.peekAndPushOrDoNothing(new Object[]{HttpRequestResponse.deepCopy(requestResponse), rowIndex},
                    Evidencer.undo
            );
        }

        if (colIndex == Utils.COMMENT_COLUMN) {
            requestResponse.setComment(value.toString());
        } else if (colIndex == Utils.CWE_COLUMN || colIndex == Utils.DESCRIPTION_COLUMN) {
            String[] split = value.toString().split(Utils.SEPARATOR);
            if (split.length == 2) {
                requestResponse.setCwe(split[0]);
                requestResponse.setDescription(split[1]);
                // We assume that selecting a CWE means attack was successful, so we proceed with highlighting the evidence
                requestResponse.setHighlight(Utils.RED_COLOR);
                requestResponse.setForegroundColor(Utils.getForegroundColorFromHighlightColor(Utils.RED_COLOR));
                requestResponse.setAttackWasSuccessful(true);
            } else {
                // There was nothing stored previously
                requestResponse.setCwe("");
                requestResponse.setDescription("");
            }
        } else if (colIndex == Utils.TO_COLUMN) {
            requestResponse.setObjective(value.toString());
        } else if (colIndex == Utils.ATTACK_SUCCESSFUL_COLUMN && value instanceof Boolean) {
            requestResponse.setAttackWasSuccessful((Boolean) value);
            // If attack was successful we automatically highlight the request depending on the risk associated to it...
            if ((Boolean) value) {
                requestResponse.setHighlight(Utils.RED_COLOR);
                requestResponse.setForegroundColor(Utils.getForegroundColorFromHighlightColor(Utils.RED_COLOR));
            } else {
                requestResponse.setHighlight(Utils.WHITE_COLOR);
                requestResponse.setForegroundColor(Utils.BLACK_COLOR);
                // We also need to clear CWE field
                requestResponse.setCwe("");
                requestResponse.setDescription("");
            }
        } else if (colIndex == Utils.HIGHLIGHT_COLUMN) {
            requestResponse.setHighlight(value.toString());
            requestResponse.setForegroundColor(Utils.getForegroundColorFromHighlightColor(value.toString()));
        }
        // Update UI
        fireTableRowsUpdated(rowIndex, rowIndex);
        // Save changes to log file
        Utils.saveToLogFile(Utils.LOGFILE, false);
    }

    String getColorForRow(int rowIndex) {
        return Evidencer.httpRequestResponses.get(Evidencer.evidencerTable.convertRowIndexToModel(rowIndex)).highlight;
    }

    String getFontColorForRow(int rowIndex) {
        return Evidencer.httpRequestResponses.get(Evidencer.evidencerTable.convertRowIndexToModel(rowIndex)).foregroundColor;
    }

    /**
     * Remove evidences
     *
     * @param rows all row ids of evidences to remove
     */
    void removeAll(int[] rows) {
        ArrayList<HttpRequestResponse> toRemove = new ArrayList<>();
        Arrays.stream(rows).forEach(row -> toRemove.add(Evidencer.httpRequestResponses.get(row)));
        // Remove the evidences
        Evidencer.httpRequestResponses.removeAll(toRemove);
        // Add to the undo stack
        Utils.peekAndPushOrDoNothing(new Object[]{toRemove, "removed"},
                Evidencer.undo
        );
        // Update UI
        fireTableDataChanged();
        // Save the current state
        Utils.saveToLogFile(Utils.LOGFILE, false);
    }

    /**
     * Remove the assigned CWE rating
     *
     * @param rows all row ids of evidences to remove
     */
    void removeCWE(int[] rows) {
        for (int row : rows) {
            setValueAt(false, row, Utils.ATTACK_SUCCESSFUL_COLUMN);
        }
    }

}
