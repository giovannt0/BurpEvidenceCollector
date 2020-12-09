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

import javax.swing.*;

/**
 * Burp extension - Evidencer
 * <p>
 * When filtering the test objectives, update the entries visible in the evidence table
 *
 * @author: Theo Giovanna - https://github.com/giovannt0
 */
class EvidencerWorker extends SwingWorker<Object, Object> {

    private final RowFilter<EvidencerTableModel, Number> filter;
    private Evidencer evidencer;

    EvidencerWorker(Evidencer evidenceCollector, RowFilter<EvidencerTableModel, Number> filter) {
        this.evidencer = evidenceCollector;
        this.filter = filter;
    }

    @Override
    protected Object doInBackground() {
        evidencer.evidenceTableSorter.setRowFilter(filter);
        return null;
    }

    @Override
    protected void done() {
        Evidencer.evidencerTable.repaint();
    }
}
