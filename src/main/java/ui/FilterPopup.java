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
import evidencer.Utils;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.util.Arrays;
import java.util.List;


/**
 * Burp extension - Evidencer
 * <p>
 * Implement a filtering popup for sorting evidences.
 *
 * @author: Theo Giovanna - https://github.com/giovannt0
 */
final class FilterPopup extends JPanel {


    private JPanel evidenceFilterByObjective = new JPanel();

    JPanel evidenceFilterBottom = new JPanel();
    JButton evidenceFilterDefaults = new JButton();
    JButton evidenceFilterSelectAll = new JButton();
    JButton evidenceFilterDeselectAll = new JButton();

    // Filters
    JCheckBox evidenceFilterA1 = new JCheckBox();
    JCheckBox evidenceFilterA1Only = new JCheckBox();
    JCheckBox evidenceFilterA2 = new JCheckBox();
    JCheckBox evidenceFilterA2Only = new JCheckBox();
    JCheckBox evidenceFilterA3 = new JCheckBox();
    JCheckBox evidenceFilterA3Only = new JCheckBox();
    JCheckBox evidenceFilterA4 = new JCheckBox();
    JCheckBox evidenceFilterA4Only = new JCheckBox();
    JCheckBox evidenceFilterA5 = new JCheckBox();
    JCheckBox evidenceFilterA5Only = new JCheckBox();
    JCheckBox evidenceFilterA6 = new JCheckBox();
    JCheckBox evidenceFilterA6Only = new JCheckBox();
    JCheckBox evidenceFilterA7 = new JCheckBox();
    JCheckBox evidenceFilterA7Only = new JCheckBox();
    JCheckBox evidenceFilterA8 = new JCheckBox();
    JCheckBox evidenceFilterA8Only = new JCheckBox();
    JCheckBox evidenceFilterA9 = new JCheckBox();
    JCheckBox evidenceFilterA9Only = new JCheckBox();
    JCheckBox evidenceFilterA10 = new JCheckBox();
    JCheckBox evidenceFilterA10Only = new JCheckBox();
    boolean evidenceFilterA1OnlyOrigin;
    boolean evidenceFilterA2OnlyOrigin;
    boolean evidenceFilterA3OnlyOrigin;
    boolean evidenceFilterA4OnlyOrigin;
    boolean evidenceFilterA5OnlyOrigin;
    boolean evidenceFilterA6OnlyOrigin;
    boolean evidenceFilterA7OnlyOrigin;
    boolean evidenceFilterA8OnlyOrigin;
    boolean evidenceFilterA9OnlyOrigin;
    boolean evidenceFilterA10OnlyOrigin;
    boolean evidenceFilterPopupReady;

    List<JCheckBox> evidenceFilters = Arrays.asList(evidenceFilterA1, evidenceFilterA2, evidenceFilterA3,
            evidenceFilterA4, evidenceFilterA5, evidenceFilterA6, evidenceFilterA7, evidenceFilterA8,
            evidenceFilterA9, evidenceFilterA10
    );
    List<JCheckBox> evidenceFiltersOnly = Arrays.asList(evidenceFilterA1Only, evidenceFilterA2Only, evidenceFilterA3Only,
            evidenceFilterA4Only, evidenceFilterA5Only, evidenceFilterA6Only, evidenceFilterA7Only, evidenceFilterA8Only,
            evidenceFilterA9Only, evidenceFilterA10Only
    );

    List<Boolean> evidenceFiltersOnlyOrigin = Arrays.asList(evidenceFilterA1OnlyOrigin,
            evidenceFilterA2OnlyOrigin, evidenceFilterA3OnlyOrigin, evidenceFilterA4OnlyOrigin,
            evidenceFilterA5OnlyOrigin, evidenceFilterA6OnlyOrigin, evidenceFilterA7OnlyOrigin,
            evidenceFilterA8OnlyOrigin, evidenceFilterA9OnlyOrigin, evidenceFilterA10OnlyOrigin);

    FilterPopup() {
        initComponents();
        TitledBorder evidenceFilterByBorder = (TitledBorder) evidenceFilterByObjective.getBorder();
        evidenceFilterByBorder.setTitleFont(evidenceFilterByBorder.getTitleFont().deriveFont(Font.PLAIN));
        BurpExtender.callbacks.customizeUiComponent(evidenceFilterA1);
        BurpExtender.callbacks.customizeUiComponent(evidenceFilterA1Only);
    }

    private void initComponents() {
        setBorder(
                BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(UIManager.getDefaults().getColor("Table.background"), 2),
                BorderFactory.createCompoundBorder(BorderFactory.createLineBorder(java.awt.Color.darkGray),
                BorderFactory.createEmptyBorder(5, 5, 5, 5))
        ));

        evidenceFilterByObjective.setBorder(BorderFactory.createTitledBorder("Filter search"));
        // Set each filter name
        for (int i=0; i<evidenceFilters.size(); i++) evidenceFilters.get(i).setText(Utils.OBJECTIVES.get(i));
        // Set "only" for only filters
        evidenceFiltersOnly.forEach(filter -> filter.setText("Only"));

        GroupLayout evidenceFilterByObjectiveLayout = new GroupLayout(evidenceFilterByObjective);
        evidenceFilterByObjective.setLayout(evidenceFilterByObjectiveLayout);

        GroupLayout.ParallelGroup horizontalGroup = evidenceFilterByObjectiveLayout.createParallelGroup(GroupLayout.Alignment.LEADING);
        for (int i=0; i<evidenceFilters.size(); i++) {
            horizontalGroup.addGroup(
                    evidenceFilterByObjectiveLayout.createSequentialGroup()
                            .addComponent(evidenceFilters.get(i))
                            .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addComponent(evidenceFiltersOnly.get(i))
            );
        }
        evidenceFilterByObjectiveLayout.setHorizontalGroup(horizontalGroup);

        GroupLayout.ParallelGroup verticalGroup = evidenceFilterByObjectiveLayout.createParallelGroup(GroupLayout.Alignment.LEADING);
        GroupLayout.SequentialGroup sequentialGroup = evidenceFilterByObjectiveLayout.createSequentialGroup();
        for (int i=0; i<evidenceFilters.size(); i++) {
            sequentialGroup.addGroup(evidenceFilterByObjectiveLayout
                    .createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(evidenceFilters.get(i))
                    .addComponent(evidenceFiltersOnly.get(i))
            );
            if (i != evidenceFilters.size() - 1) {
                sequentialGroup.addPreferredGap(LayoutStyle.ComponentPlacement.RELATED);
            }
        }
        verticalGroup.addGroup(sequentialGroup);
        evidenceFilterByObjectiveLayout.setVerticalGroup(verticalGroup);

        GroupLayout evidenceFilterBottomLayout = new GroupLayout(evidenceFilterBottom);
        evidenceFilterBottom.setLayout(evidenceFilterBottomLayout);
        evidenceFilterBottomLayout.setHorizontalGroup(
                evidenceFilterBottomLayout.createParallelGroup(GroupLayout.Alignment.LEADING)
                        .addGap(0, 0, Short.MAX_VALUE)
        );
        evidenceFilterBottomLayout.setVerticalGroup(
                evidenceFilterBottomLayout.createParallelGroup(GroupLayout.Alignment.LEADING)
                        .addGap(0, 0, Short.MAX_VALUE)
        );

        GroupLayout layout = new GroupLayout(this);
        this.setLayout(layout);
        layout.setHorizontalGroup(
                layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                        .addGroup(layout.createSequentialGroup()
                                .addContainerGap()
                                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                                        .addComponent(evidenceFilterDefaults, GroupLayout.PREFERRED_SIZE, 24, GroupLayout.PREFERRED_SIZE)
                                        .addComponent(evidenceFilterSelectAll, GroupLayout.PREFERRED_SIZE, 24, GroupLayout.PREFERRED_SIZE)
                                        .addComponent(evidenceFilterDeselectAll, GroupLayout.PREFERRED_SIZE, 24, GroupLayout.PREFERRED_SIZE))
                                .addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED)
                                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING))
                                .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(evidenceFilterByObjective, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
                                .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                                .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(evidenceFilterBottom, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );
        layout.setVerticalGroup(
                layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                        .addGroup(layout.createSequentialGroup()
                                .addContainerGap()
                                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                                        .addGroup(layout.createSequentialGroup()
                                                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING, false)
                                                        .addComponent(evidenceFilterByObjective, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                                                .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                                .addComponent(evidenceFilterBottom, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE))
                                        .addGroup(layout.createSequentialGroup()
                                                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                                                        .addGroup(layout.createSequentialGroup()
                                                                .addComponent(evidenceFilterDefaults, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
                                                                .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                                                                .addComponent(evidenceFilterSelectAll, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
                                                                .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                                                                .addComponent(evidenceFilterDeselectAll, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE))
                                                )
                                                .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED))))
        );
        evidenceFilterDefaults.getAccessibleContext().setAccessibleDescription("");
        evidenceFilterByObjective.getAccessibleContext().setAccessibleName("Filter ");
    }

}
